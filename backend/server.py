import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# arquivo de hashing com HMAC
import hmac_1

# biblioteca de hashing
import hmac
import hashlib


api = Flask(__name__)
CORS(api)


# @api.route("/arquivos/<nome_do_arquivo>",  methods=["GET"])
# def get_arquivo(nome_do_arquivo):
#     return "teste"


@api.route("/hash", methods=["POST"])
def hashing():
    # Verifica se a requisição é do tipo POST
    if request.method == 'POST':
        response = jsonify(methods=["POST"])
        response.headers["Access-Control-Allow-Origin"] = "*"
        # Verifica se o cabeçalho "Content-Type" é "application/json"
        if request.is_json:
            # Obtém o JSON do corpo da requisição
            json_data = request.get_json()

            # Verifica se as chaves 'mensagem' e 'senha' estão no JSON
            if 'mensagem' in json_data and 'senha' in json_data:
                message = json_data['mensagem']
                password = json_data['senha']

                # Converte a senha em bytes (você pode usar uma codificação específica se necessário)
                senha_bytes = password.encode()

                # Calcula o HMAC usando a biblioteca hmac
                hmac_resultado = hmac_1.getHash(password,message)
                # Retorne uma resposta, se necessário
                return jsonify(
                    {
                        "mensagem": message,
                        "senha": password,
                        "hashing": hmac_resultado,
                    }), {"Access-Control-Allow-Origin": "*"}
            else:
                return jsonify({"error": "Chaves 'mensagem' e 'senha' são obrigatórias"}), 400
        else:
            return jsonify({"error": "O conteúdo da requisição deve estar no formato JSON"}), 400
    else:
        return "Método não permitido", 405
    
@api.route("/getHashs", methods=[ "POST"])
def getHashs():
    # Verifica se a requisição é do tipo POST
    if request.method == 'POST':
        # Verifica se o cabeçalho "Content-Type" é "application/json"
        if request.is_json:
            # Obtém o JSON do corpo da requisição
            json_data = request.get_json()

            # Verifica se as chaves 'mensagem' e 'senha' estão no JSON
            if 'mensagem' in json_data and 'senha' in json_data:
                message = json_data['mensagem']
                password = json_data['senha']

                # Calcula o HMAC usando a biblioteca hmac
                hmac_resultado = hmac_1.getHash(password,message)


                # Converte a senha em bytes (você pode usar uma codificação específica se necessário)
                senha_bytes = password.encode()

                # Calcula o HMAC usando a biblioteca hmac
                hmac_resultado_biblioteca = hmac.new(senha_bytes, message.encode(), hashlib.sha256).hexdigest()

                # Retorne uma resposta, se necessário
                return jsonify(
                    {
                        "mensagem": message,
                        "senha": password,
                        "hash": hmac_resultado,
                        "hashlib": hmac_resultado_biblioteca
                    }), {"Access-Control-Allow-Origin": "*"}
            else:
                return jsonify({"error": "Chaves 'mensagem' e 'senha' são obrigatórias"}), 400
        else:
            return jsonify({"error": "O conteúdo da requisição deve estar no formato JSON"}), 400
    else:
        return "Método não permitido", 405


@api.route("/hash/biblioteca", methods=["POST"])
def test():
    # Verifica se a requisição é do tipo POST
    if request.method == 'POST':
        # Verifica se o cabeçalho "Content-Type" é "application/json"
        if request.is_json:
            # Obtém o JSON do corpo da requisição
            json_data = request.get_json()

            # Verifica se as chaves 'mensagem' e 'senha' estão no JSON
            if 'mensagem' in json_data and 'senha' in json_data:
                message = json_data['mensagem']
                password = json_data['senha']

                # Converte a senha em bytes (você pode usar uma codificação específica se necessário)
                senha_bytes = password.encode()

                # Calcula o HMAC usando a biblioteca hmac
                hmac_resultado_biblioteca = hmac.new(senha_bytes, message.encode(), hashlib.sha256).hexdigest()

                # Retorne uma resposta, se necessário
                return jsonify(
                    {
                        "mensagem": message,
                        "senha": password,
                        "hashing": hmac_resultado_biblioteca,
                    }), 200
            else:
                return jsonify({"error": "Chaves 'mensagem' e 'senha' são obrigatórias"}), 400
        else:
            return jsonify({"error": "O conteúdo da requisição deve estar no formato JSON"}), 400
    else:
        return "Método não permitido", 405
    


if __name__ == "__main__":
    api.run(host='0.0.0.0', port=8888, debug=True)