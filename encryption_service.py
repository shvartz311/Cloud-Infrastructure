import os

from jfrogdevopstools.tools.functions import convert_str_to_bin
from jfrogdevopstools.tools.functions import decrypt_msg


class EncryptionService:
    CONFIG_PREFIX_BINARY = "config_binary-"  # prefix to mark the value is binary (like: "$ANSIBLE_VAULT;1.1;AES256")

    def decrypt(self, encrypted_str: str) -> str:
        config_str = encrypted_str.replace(self.CONFIG_PREFIX_BINARY, "")
        binary_bytes = convert_str_to_bin(config_str)

        return decrypt_msg(ciphertext=binary_bytes, decryptor_type="kms")

