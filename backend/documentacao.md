# Documentação

## HMAC_1.py
### Função sha256
    Esta função implementa um cálculo simples do hash SHA-256 (Secure Hash Algorithm 256 bits). SHA-256 é uma função hash criptográfica amplamente utilizada para gerar hashes de mensagens. A função sha256 recebe uma mensagem como entrada e retorna o hash SHA-256 correspondente da mensagem.

#### Parâmetros
    message (bytes): A mensagem para a qual o hash SHA-256 será calculado.
    Retorno
    bytes: O hash SHA-256 da mensagem fornecida, representado como uma sequência de bytes.
### Função hmac_sha256
    Esta função implementa o cálculo de um HMAC (Hash-based Message Authentication Code) usando o algoritmo SHA-256. O HMAC é frequentemente usado para verificar a integridade e a autenticidade de mensagens. A função hmac_sha256 recebe uma chave secreta e uma mensagem como entrada e retorna o HMAC-SHA-256 correspondente da mensagem usando a chave secreta.

#### Parâmetros
    key (str): A chave secreta usada para calcular o HMAC.
    message (str): A mensagem à qual o HMAC será aplicado.
    Retorno
    bytes: O HMAC-SHA-256 da mensagem usando a chave secreta, representado como uma sequência de bytes.

### Função pad_message
    Esta função é responsável por preencher a mensagem de entrada com o padding necessário para o cálculo do hash SHA-256. O padding é uma técnica usada em algoritmos de hash para garantir que a mensagem tenha um tamanho específico antes do cálculo do hash.

#### Parâmetros
    message (bytes): A mensagem que precisa ser preenchida com o padding.
    Retorno
    bytes: A mensagem original com o padding aplicado, representado como uma sequência de bytes.

### Função getHash
    Esta função é uma função de conveniência que calcula o HMAC-SHA-256 de uma mensagem usando uma chave secreta e retorna o resultado como uma representação hexadecimal.