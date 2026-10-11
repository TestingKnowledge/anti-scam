import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import discord
from aiohttp import web

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("anti-scam-bot")


def required_int(name: str) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a numeric Discord ID") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive integer")
    return parsed


def bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
TRIGGER_CHANNEL_ID = required_int("TRIGGER_CHANNEL_ID")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0") or "0")
TIMEOUT_MINUTES = bounded_int("TIMEOUT_MINUTES", 10080, 1, 40320)  # 7 days by default; max 28 days
CLEANUP_LOOKBACK_MINUTES = bounded_int("CLEANUP_LOOKBACK_MINUTES", 60, 1, 10080)
MAX_MESSAGES_PER_CHANNEL = bounded_int("MAX_MESSAGES_PER_CHANNEL", 1000, 1, 5000)

if not TOKEN:
    raise RuntimeError("Missing required environment variable: DISCORD_TOKEN")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
# Message content is intentionally not enabled: the bot only watches a configured channel ID.
intents.message_content = False

async def health_handler(request: web.Request) -> web.Response:
    client = request.app["discord_client"]
    ready = client.is_ready()
    return web.json_response(
        {"status": "ok" if ready else "starting", "discord_ready": ready},
        status=200 if ready else 503,
    )


class AntiScamClient(discord.Client):
    def __init__(self, *, intents: discord.Intents):
        super().__init__(intents=intents)
        self.health_runner: web.AppRunner | None = None

    async def setup_hook(self) -> None:
        await super().setup_hook()
        try:
            port = int(os.getenv("PORT", "8080"))
            if not 1 <= port <= 65535:
                raise ValueError("PORT must be between 1 and 65535")
        except ValueError as exc:
            raise RuntimeError("PORT must be a valid TCP port number") from exc

        app = web.Application()
        app["discord_client"] = self
        app.router.add_get("/", health_handler)
        app.router.add_get("/health", health_handler)
        self.health_runner = web.AppRunner(app)
        await self.health_runner.setup()
        site = web.TCPSite(self.health_runner, host="0.0.0.0", port=port)
        await site.start()
        log.info("HTTP health endpoint listening on 0.0.0.0:%s (/health)", port)

    async def close(self) -> None:
        if self.health_runner is not None:
            await self.health_runner.cleanup()
            self.health_runner = None
        await super().close()


bot = AntiScamClient(intents=intents)
processing_members: set[tuple[int, int]] = set()
WARNING_TEXT = "DONT TYPE HERE OR YOU WILL GET MUTTED"
warning_pin_lock = asyncio.Lock()


def is_exempt(member: discord.Member) -> bool:
    """Avoid accidental self-triggering by the server owner and moderation staff."""
    perms = member.guild_permissions
    return (
        member.id == member.guild.owner_id
        or perms.administrator
        or perms.manage_guild
        or perms.manage_messages
    )


async def send_mod_log(guild: discord.Guild, content: str) -> None:
    if not LOG_CHANNEL_ID:
        log.info(content)
        return
    channel = guild.get_channel(LOG_CHANNEL_ID)
    if channel is None:
        try:
            channel = await bot.fetch_channel(LOG_CHANNEL_ID)
        except (discord.Forbidden, discord.NotFound, discord.HTTPException):
            log.warning("Could not access LOG_CHANNEL_ID=%s. %s", LOG_CHANNEL_ID, content)
            return
    if not isinstance(channel, (discord.TextChannel, discord.Thread)):
        log.warning("LOG_CHANNEL_ID is not a text channel or thread. %s", content)
        return
    try:
        await channel.send(content[:1900], allowed_mentions=discord.AllowedMentions.none())
    except (discord.Forbidden, discord.NotFound, discord.HTTPException) as exc:
        log.warning("Could not post moderation log: %s", exc)


async def delete_recent_messages(guild: discord.Guild, member_id: int) -> tuple[int, int, int]:
    """Delete this member's messages newer than the cutoff from channels the bot can manage."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=CLEANUP_LOOKBACK_MINUTES)
    channels: list[discord.abc.Messageable] = []
    seen_channel_ids: set[int] = set()

    # Include regular text channels and currently active threads (including forum posts).
    for channel in [*guild.text_channels, *guild.threads]:
        if channel.id not in seen_channel_ids:
            seen_channel_ids.add(channel.id)
            channels.append(channel)

    deleted = 0
    scanned = 0
    inaccessible = 0

    for channel in channels:
        # Only try places in which the bot can see history and delete other users' messages.
        permissions = channel.permissions_for(guild.me) if guild.me else None
        if not permissions or not permissions.view_channel or not permissions.read_message_history:
            inaccessible += 1
            continue
        if not permissions.manage_messages:
            inaccessible += 1
            continue

        try:
            async for old_message in channel.history(
                limit=MAX_MESSAGES_PER_CHANNEL,
                after=cutoff,
                oldest_first=False,
            ):
                scanned += 1
                if old_message.author.id != member_id:
                    continue
                try:
                    await old_message.delete()
                    deleted += 1
                except discord.NotFound:
                    pass  # Already deleted by another moderator or bot.
                except (discord.Forbidden, discord.HTTPException) as exc:
                    log.warning("Could not delete message %s in channel %s: %s", old_message.id, channel.id, exc)
        except (discord.Forbidden, discord.NotFound, discord.HTTPException) as exc:
            log.warning("Could not scan channel %s (%s): %s", getattr(channel, "id", "?"), getattr(channel, "name", "?"), exc)

    return deleted, scanned, inaccessible


async def ensure_trigger_warning_pinned() -> None:
    """Ensure the warning exists and is pinned without creating duplicates on reconnects."""
    async with warning_pin_lock:
        channel = bot.get_channel(TRIGGER_CHANNEL_ID)
        if channel is None:
            try:
                channel = await bot.fetch_channel(TRIGGER_CHANNEL_ID)
            except (discord.Forbidden, discord.NotFound, discord.HTTPException) as exc:
                log.error("Could not access trigger channel %s to pin the warning: %s", TRIGGER_CHANNEL_ID, exc)
                return

        if not isinstance(channel, discord.TextChannel):
            log.error("TRIGGER_CHANNEL_ID=%s is not a server text channel; cannot pin the warning", TRIGGER_CHANNEL_ID)
            return

        bot_user = bot.user
        if bot_user is None:
            log.warning("Bot user is not available yet; warning was not pinned")
            return

        try:
            async for pinned in channel.pins():
                if pinned.author.id == bot_user.id and pinned.content.strip() == WARNING_TEXT:
                    log.info("Trigger warning is already pinned in #%s", channel.name)
                    return

            # If a previous run sent the warning but could not pin it, pin that message.
            async for recent in channel.history(limit=100, oldest_first=False):
                if recent.author.id == bot_user.id and recent.content.strip() == WARNING_TEXT:
                    await recent.pin(reason="Keep the anti-scam trigger-channel warning visible")
                    log.info("Pinned existing trigger warning in #%s", channel.name)
                    return

            warning = await channel.send(WARNING_TEXT, allowed_mentions=discord.AllowedMentions.none())
            await warning.pin(reason="Keep the anti-scam trigger-channel warning visible")
            log.info("Posted and pinned trigger warning in #%s", channel.name)
        except discord.Forbidden:
            log.error(
                "Cannot read history/send/pin in trigger channel %s; grant View Channel, Read Message History, Send Messages, and Manage Messages",
                TRIGGER_CHANNEL_ID,
            )
        except discord.HTTPException as exc:
            log.error("Discord API error while pinning trigger-channel warning: %s", exc)


@bot.event
async def on_ready() -> None:
    log.info("Logged in as %s (ID %s)", bot.user, bot.user.id if bot.user else "unknown")
    log.info("Trigger channel ID: %s", TRIGGER_CHANNEL_ID)
    log.info(
        "Timeout=%s minutes | Cleanup lookback=%s minutes | Max messages/channel=%s",
        TIMEOUT_MINUTES,
        CLEANUP_LOOKBACK_MINUTES,
        MAX_MESSAGES_PER_CHANNEL,
    )
    await ensure_trigger_warning_pinned()


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.guild is None or message.author.bot:
        return
    if message.channel.id != TRIGGER_CHANNEL_ID:
        return
    if not isinstance(message.author, discord.Member):
        return

    member = message.author
    if is_exempt(member):
        log.info("Ignored trigger message from exempt staff member %s (%s)", member, member.id)
        return

    key = (message.guild.id, member.id)
    if key in processing_members:
        return
    processing_members.add(key)

    try:
        trigger_deleted = False
        try:
            await message.delete()
            trigger_deleted = True
        except discord.NotFound:
            trigger_deleted = True
        except (discord.Forbidden, discord.HTTPException) as exc:
            log.warning("Could not delete trigger message %s: %s", message.id, exc)

        timeout_ok = False
        try:
            await member.timeout(
                timedelta(minutes=TIMEOUT_MINUTES),
                reason="Message posted in the server's designated anti-scam alert channel",
            )
            timeout_ok = True
        except discord.Forbidden:
            log.warning("Cannot timeout %s (%s): check Moderate Members permission and role hierarchy", member, member.id)
        except discord.HTTPException as exc:
            log.warning("Timeout failed for %s (%s): %s", member, member.id, exc)

        deleted, scanned, inaccessible = await delete_recent_messages(message.guild, member.id)
        status = (
            f"Anti-scam trigger: {member} (ID {member.id}) posted in <#{TRIGGER_CHANNEL_ID}>. "
            f"Trigger message deleted: {trigger_deleted}. Timeout applied: {timeout_ok} "
            f"({TIMEOUT_MINUTES} minutes). Recent messages deleted: {deleted}. "
            f"Messages checked: {scanned}. Channels/threads skipped or inaccessible: {inaccessible}."
        )
        log.warning(status)
        await send_mod_log(message.guild, status)

    except Exception:
        log.exception("Unexpected error while processing anti-scam trigger for member %s", member.id)
    finally:
        processing_members.discard(key)


if __name__ == "__main__":
    try:
        bot.run(TOKEN, log_handler=None)
    except KeyboardInterrupt:
        log.info("Bot stopped")
