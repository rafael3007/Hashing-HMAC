# Aplicação de Hash HMAC com Next.js e Flask

Esta é uma aplicação de exemplo que demonstra a criação de um hash HMAC (Hash-based Message Authentication Code) usando Next.js no frontend e Flask no backend. O hash HMAC é gerado com base em uma mensagem e uma senha inseridas pelo usuário. Além disso, a aplicação mostra dois resultados de hash: um calculado com um algoritmo personalizado em Python e outro usando uma biblioteca pronta.

#### Parâmetros
    password (str): A chave secreta usada para calcular o HMAC.
    message (str): A mensagem à qual o HMAC será aplicado.
    Retorno
    str: O HMAC-SHA-256 da mensagem usando a chave secreta, representado como uma string hexadecimal.


# Pré-requisitos

- Node.js (versão igual ou superior a 13)
- Python (versão igual ou superior a 3.7)
- Flask (instalado via `pip install flask`)
- Axios (instalado via `npm install axios`)
- Tailwind CSS (opcional, para estilização)

# Instalação

1. Clone o repositório para o seu ambiente local:

```bash
git clone https://github.com/seu-usuario/seu-repositorio.git
cd seu-repositorio
Instale as dependências do frontend:
```
```bash
Copy code
cd frontend
npm install
Instale as dependências do backend:
```
```bash
Copy code
cd backend
pip install -r requirements.txt
Executando a Aplicação
Inicie o servidor Flask no diretório backend:
```
```bash
Copy code
cd backend
python server.py
O servidor estará em execução na porta 8888.
```
2. Inicie o frontend em um terminal separado:
```bash
Copy code
cd frontend
npm run dev
A aplicação estará disponível em http://localhost:3000.
```

# Como Usar
    Abra a aplicação no seu navegador em http://localhost:3000.

    Preencha os campos "Mensagem" e "Senha" com os valores desejados.

    Clique no botão "Gerar hash" para calcular o hash HMAC da mensagem e senha.

    Os resultados serão exibidos na seção "Resultados":

    `Hash` mostra o resultado do cálculo personalizado em Python.
    `HashLib` mostra o resultado do cálculo usando a biblioteca hashlib.
    Testes
    Para testar a aplicação, siga as etapas acima e use a interface do usuário para gerar hashes com diferentes mensagens e senhas. Certifique-se de que os resultados dos cálculos coincidam com suas expectativas.

    `Documentação de Código``
    Os códigos-fonte da aplicação estão localizados nos diretórios frontend e backend. Consulte os arquivos .js e .py para obter detalhes sobre a implementação.


# Licença
    Este projeto é licenciado sob a Licença MIT. Consulte o arquivo LICENSE para obter mais informações.