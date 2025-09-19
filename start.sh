#!/bin/bash
# Define que o interpretador a ser usado será o Bash.

set -e
# Ativa a opção "exit on error".
# Isso significa que, caso qualquer comando retorne erro (status diferente de 0),
# o script será interrompido imediatamente.
# Essa prática evita que etapas subsequentes rodem em um ambiente inconsistente.

echo "[*] Limpando containers e imagens antigos..."
# Exibe mensagem para o usuário informando que os containers e imagens antigos
# serão removidos.

docker compose down -v || true
# "docker compose down -v" remove containers, redes e volumes associados ao projeto.
# O parâmetro "-v" remove também os volumes, garantindo uma limpeza completa.
# O "|| true" garante que, caso esse comando falhe (por exemplo, se não houver containers
# ativos), o script não será interrompido por causa do "set -e".

echo "[*] Rebuildando imagens..."
# Mensagem informando que o rebuild (reconstrução) das imagens será feito.

docker compose build --no-cache
# Reconstrói todas as imagens definidas no arquivo docker-compose.
# A opção "--no-cache" força a reconstrução do zero, sem aproveitar camadas já existentes,
# garantindo que as imagens fiquem totalmente atualizadas.

echo "[*] Subindo oracle e solver..."
# Mensagem informando que os serviços "oracle" e "solver" serão inicializados.

docker compose up -d oracle solver
# Sobe apenas os serviços "oracle" e "solver" em segundo plano (-d = detached).
# Esses serviços devem estar definidos no arquivo docker-compose.yml do projeto.

echo "[*] Aguardando oracle ficar saudável..."
# Exibe mensagem avisando que será aguardado um tempo até que o serviço "oracle"
# esteja em funcionamento.

sleep 5
# Aguarda 5 segundos.
# Essa pausa dá tempo para que o container "oracle" inicialize completamente
# e esteja pronto para receber conexões.

docker compose ps
# Lista o status atual dos containers gerenciados pelo docker-compose.
# Isso permite verificar se os serviços realmente subiram e estão rodando.

echo "[*] Executando solver contra o oracle local..."
# Informa ao usuário que o script "solver" será executado contra o serviço "oracle".

docker compose exec solver python -u /app/solve_delphi.py oracle 4356
# Executa o script Python "solve_delphi.py" dentro do container "solver".
# O parâmetro "-u" (unbuffered) força a saída em tempo real, útil para acompanhar logs.
# Argumentos passados ao script:
#   - "oracle" → nome do serviço alvo dentro da rede do docker-compose.
#   - "4356" → porta na qual o "oracle" está escutando.
# Dessa forma, o solver se conecta ao oracle local para executar a lógica do desafio.
