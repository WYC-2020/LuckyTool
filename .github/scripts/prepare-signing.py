import base64
import os
from pathlib import Path
import secrets
import subprocess


def escape_property(value):
    encoded = value.encode("utf-16-be")
    return "".join(
        "\\u" + encoded[index:index + 2].hex()
        for index in range(0, len(encoded), 2)
    )


def main():
    secret_names = (
        "SIGNING_KEYSTORE_BASE64",
        "SIGNING_STORE_PASSWORD",
        "SIGNING_KEY_ALIAS",
        "SIGNING_KEY_PASSWORD",
    )
    signing = {name: os.environ.get(name, "") for name in secret_names}
    if any(signing.values()) and not all(signing.values()):
        raise SystemExit("All four SIGNING_* secrets must be configured together.")

    keystore_path = Path(os.environ["RUNNER_TEMP"]) / "luckytool-signing.jks"
    keystore_path.touch(mode=0o600, exist_ok=False)
    if all(signing.values()):
        keystore_path.write_bytes(base64.b64decode(
            "".join(signing["SIGNING_KEYSTORE_BASE64"].split()), validate=True
        ))
    else:
        print("::warning::No signing secrets configured. Using a temporary signing key; "
              "APKs from different runs cannot update each other.", flush=True)
        password = secrets.token_hex(24)
        print("::add-mask::" + password, flush=True)
        signing["SIGNING_STORE_PASSWORD"] = password
        signing["SIGNING_KEY_PASSWORD"] = password
        signing["SIGNING_KEY_ALIAS"] = "luckytool-ci"
        keystore_path.unlink()
        subprocess.run([
            "keytool", "-genkeypair", "-noprompt",
            "-keystore", str(keystore_path), "-storetype", "JKS",
            "-alias", signing["SIGNING_KEY_ALIAS"],
            "-storepass:env", "CI_STORE_PASSWORD",
            "-keypass:env", "CI_KEY_PASSWORD",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=LuckyTool CI, OU=Development, O=LuckyTool, C=CN",
        ], check=True, env={
            **os.environ,
            "CI_STORE_PASSWORD": password,
            "CI_KEY_PASSWORD": password,
        })
        keystore_path.chmod(0o600)

    properties = {
        "storeFile": keystore_path.as_posix(),
        "storePassword": signing["SIGNING_STORE_PASSWORD"],
        "keyAlias": signing["SIGNING_KEY_ALIAS"],
        "keyPassword": signing["SIGNING_KEY_PASSWORD"],
    }
    properties_path = Path("keystore/keystore.properties")
    properties_path.parent.mkdir(parents=True, exist_ok=True)
    properties_path.touch(mode=0o600, exist_ok=False)
    properties_path.write_text(
        "".join(name + "=" + escape_property(value) + "\n"
                for name, value in properties.items()),
        encoding="ascii",
    )


if __name__ == "__main__":
    main()
