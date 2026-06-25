import json
import secrets

with open("config.json", "r+") as file:
    json_data = json.load(file)
    json_data["hmac_key"] = secrets.token_hex(32)
    file.seek(0)
    json.dump(json_data, file, indent=4)
    file.truncate()

print("\n[*] Key Generated.")