"""
Telegram alert sender for LogSentinelAI

Sends alert messages to a Telegram group when called.
Uses python-telegram-bot and .env config for TELEGRAM_TOKEN and TELEGRAM_CHAT_ID.
"""
import os
from dotenv import load_dotenv
from telegram import Bot
from telegram.ext import Application
import asyncio

# Load environment variables from config (already loaded in main app, but safe here)
load_dotenv(os.getenv("CONFIG_FILE_PATH", "./config"), override=True)

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    raise RuntimeError("TELEGRAM_TOKEN and TELEGRAM_CHAT_ID must be set in config or .env file.")

def send_telegram_alert(message: str) -> None:
    """Send a message to the configured Telegram group."""
    async def _send_async():
        # Create a new bot instance for each message to avoid connection pool issues
        async with Bot(token=TELEGRAM_TOKEN) as bot:
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)
    
    try:
        # Try to run in new event loop
        asyncio.run(_send_async())
    except RuntimeError as e:
        if "cannot be called from a running event loop" in str(e):
            # Already in an event loop, create a task
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create task for running loop
                    task = loop.create_task(_send_async())
                    # Since we can't await in sync function, we'll use a different approach
                    # Use threading to run the async operation
                    import threading
                    import concurrent.futures
                    
                    def run_in_thread():
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        try:
                            new_loop.run_until_complete(_send_async())
                        finally:
                            new_loop.close()
                    
                    thread = threading.Thread(target=run_in_thread)
                    thread.start()
                    thread.join(timeout=30)  # 30초 타임아웃
                else:
                    loop.run_until_complete(_send_async())
            except Exception as inner_e:
                raise RuntimeError(f"Failed to send Telegram message: {inner_e}")
        else:
            raise e
