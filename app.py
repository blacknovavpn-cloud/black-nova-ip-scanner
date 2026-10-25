from flask import Flask, request, jsonify
import socket
import ssl
import ipaddress

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "name": "BLACK NOVA IP Scanner",
        "status": "online"
    })

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    target = str(data.get("ip", "")).strip()
    port = data.get("port", 443)

    try:
        address = ipaddress.ip_address(target)
        if not address.is_global:
            return jsonify({"error": "Public IP required"}), 400

        port = int(port)
        if port not in (80, 443):
            return jsonify({"error": "Only ports 80 and 443 allowed"}), 400

        with socket.create_connection(
            (str(address), port), timeout=3
        ) as connection:
            result = {"ip": target, "port": port, "reachable": True}

            if port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(
                    connection, server_hostname=str(address)
                ) as secure:
                    result["tls"] = secure.version()

            return jsonify(result)

    except (ValueError, OSError, ssl.SSLError) as error:
        return jsonify({
            "ip": target,
            "reachable": False,
            "error": str(error)
        }), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
