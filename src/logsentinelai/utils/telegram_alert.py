"""
Telegram alert sender for LogSentinelAI

Sends alert messages to a Telegram group when called.
Uses python-telegram-bot and .env config for TELEGRAM_TOKEN and TELEGRAM_CHAT_ID.
"""
import os
from dotenv import load_dotenv
from telegram import Bot

# Load environment variables from config (already loaded in main app, but safe here)
load_dotenv(os.getenv("CONFIG_FILE_PATH", "./config"), override=True)

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    raise RuntimeError("TELEGRAM_TOKEN and TELEGRAM_CHAT_ID must be set in config or .env file.")

bot = Bot(token=TELEGRAM_TOKEN)

import asyncio

def send_telegram_alert(message: str) -> None:
    """Send a message to the configured Telegram group."""
    async def _send():
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
    try:
        asyncio.run(_send())
    except RuntimeError:
        # 이미 이벤트 루프가 실행 중인 경우(예: Jupyter 등)
        loop = asyncio.get_event_loop()
        loop.create_task(_send())
