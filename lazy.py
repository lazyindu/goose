import base64
import telebot

# Initialize the bot with your token
bot = telebot.TeleBot('6045043208:AAFSpU6PZBBeIfo0nj6r8jC1w7wVxSfCTlE')

# First, delete any existing webhook
bot.remove_webhook()

# Now start polling
bot.polling() 

def xor_encrypt_decrypt(data: bytes, key: str) -> bytes:
    # XOR decryption using the provided key
    decrypted_bytes = bytearray()
    key_bytes = key.encode()

    for i in range(len(data)):
        decrypted_bytes.append(data[i] ^ key_bytes[i % len(key_bytes)])

    return decrypted_bytes

# Read the encrypted script file in binary mode
with open('lazydeveloper.py.enc', 'rb') as file:
    encrypted_script_base64 = file.read()

# Decode the base64-encoded data
encrypted_script = base64.b64decode(encrypted_script_base64)

# Decrypt using XOR
key = 'YT@LazyDeveloperr'
decrypted_script = xor_encrypt_decrypt(encrypted_script, key)

# Execute the decrypted script
exec(decrypted_script.decode('latin1'))  # Use 'latin1' to handle byte to string conversion
