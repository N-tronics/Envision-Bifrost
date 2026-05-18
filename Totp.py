import hashlib
import hmac
import struct
import time


def generate_totp(shared_secret):
    # --- STEP 1: PREPARE THE SECRET ---
    digital_key = int(shared_secret).to_bytes(8, byteorder="big")

    # --- STEP 2: CHECK THE CLOCK ---
    current_seconds = time.time()
    thirty_second_window = int(current_seconds / 30)

    time_message = struct.pack(">Q", thirty_second_window)

    # --- STEP 3: THE DIGITAL BLENDER (HMAC) ---
    hash_result = hmac.new(digital_key, time_message, hashlib.sha1).digest()

    # --- STEP 4: PICKING THE NUMBERS ---
    start_position = hash_result[-1] & 0x0F

    # We grab 4 bytes of data starting from that position.
    grabbed_data = hash_result[start_position : start_position + 4]

    # Turn those 4 bytes into a single big whole number.
    big_number = struct.unpack(">I", grabbed_data)[0] & 0x7FFFFFFF

    # --- STEP 5: THE 6-DIGIT SQUISH ---
    six_digit_code = big_number % 1000000

    return str(six_digit_code).zfill(6)


# --- QUICK TEST AREA ---
if __name__ == "__main__":
    test_secret = "my_super_secret_key"
    print(f"Your 6-digit code for right now is: {generate_totp(test_secret)}")
    print("Wait 30 seconds and run it again to see it change!")
