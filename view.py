from flask import Flask, jsonify, request, send_file
from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
from fpdf import FPDF
from datetime import datetime
import re
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from flask_apscheduler import APScheduler
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import base64
import requests
import tempfile
import os
import qrcode
from qrcode.constants import ERROR_CORRECT_H
import crcmod
import random

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

#========================================================================================================================================
def enviar_email(email, html_corpo):
    if not email:
        raise ValueError("Endereço de e-mail não fornecido.")

    subject = "🎟️ EQUIPE - Cinestrelar"
    sender = "cinestelar123@gmail.com"
    recipients = [email]
    password = "vpjf svex wbcj ndeq"  # dica: use variáveis de ambiente em produção!

    try:
        # Estrutura principal (multipart/alternative)
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)

        # Adiciona o corpo HTML
        msg.attach(MIMEText(html_corpo, 'html', 'utf-8'))

        # Envia o e-mail
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipients, msg.as_string())

        print("✅ E-mail enviado com sucesso!")

    except Exception as e:
        print(f"❌ Ocorreu um erro ao enviar o e-mail: {e}")
def validar_senha(senha):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', senha))#requisitos da senha
def generate_token(user_id, email):
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        # Onde os arquivos serão salvos, caso ele não exista será criado.
        os.makedirs(app.config['UPLOAD_FOLDER'])
    payload = {'id_usuario': user_id, 'email': email}
    # Define o payload onde vai definir as informações que serão passadas para o token.
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    # Faz com que o token seja gerado com as informações do payload e uma senha secreta.
    return token
def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token
def verifica_adm(id):
    cur = con.cursor()
    cur.execute("SELECT COALESCE(cargo, '') FROM cadastro where id_cadastro = ? and cargo = ?", (id, 'ADM'))
    usuario = cur.fetchone()
    cur.close()

    if usuario and usuario[0] == 'ADM':
        return True
    return False
def bloquear_sessoes_vencidas():
    agora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor = con.cursor()
    cursor.execute("UPDATE sessao SET status = 1 WHERE datasessao < ? AND status != 1", (agora,))
    con.commit()  # Isso já libera o cursor
    print(f"[{agora}] Sessões vencidas foram bloqueadas.")
#========================================================================================================================================
class Config:
    SCHEDULER_API_ENABLED = True

# Aplica config e inicia agendador
app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Agenda a função para rodar a cada minuto
scheduler.add_job(id='BloquearSessoesVencidas', func=bloquear_sessoes_vencidas, trigger='interval', minutes=43200)
#========================================================================================================================================
@app.route('/cadastro', methods=['GET'])
def lista_usuario():
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, cpf, data_nascimento, email, CASE cidade WHEN 1 THEN 'Birigui' WHEN 2 THEN 'Araçatuba' END cidade , cargo FROM cadastro")
    usuarios = cur.fetchall()
    cur.close()

    usuarios_lista = [{
        'id_cadastro': cadastro[0],
        'nome': cadastro[1],
        'cpf': cadastro[2],
        'data_nascimento': cadastro[3],
        'email': cadastro[4],
        'cidade': cadastro[5],
        'cargo': cadastro[6]
    } for cadastro in usuarios]

    return jsonify({'mensagem': 'Lista de usuários', 'cadastro': usuarios_lista})
@app.route('/cadastro', methods=['POST'])
def criar_usuario():
    data = request.get_json()
    nome = data.get('nome')
    cpf = data.get('cpf')
    data_nascimento = data.get('data_nascimento')
    email = data.get('email')
    cidade = data.get('cidade')
    senha = data.get('senha')
    cargo = data.get('cargo')

    if not validar_senha(senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, um número e um caractere especial."})

    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cursor.fetchone():
        return jsonify({"error": "Usuário já cadastrado"})

    senha_hash = generate_password_hash(senha).decode('utf-8')

    cursor.execute("INSERT INTO cadastro (nome, cpf, data_nascimento, email, cidade, senha, cargo) VALUES (?,?,?,?,?,?,?)",
                   (nome, cpf, data_nascimento, email, cidade, senha_hash, cargo))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Usuário cadastrado com sucesso!'})
@app.route('/cadastro/<int:id>', methods=['PUT'])  #editar a conta
def atualizar_usuario(id):
    data = request.get_json()
    email = data.get('email')
    nome = data.get('nome')
    senha = data.get('senha')
    cpf = data.get('cpf')
    cidade = data.get('cidade')
    data_nascimento = data.get('data_nascimento')

    cursor = con.cursor()
    cursor.execute("SELECT id_cadastro FROM cadastro WHERE id_cadastro = ?", (id,))
    if not cursor.fetchone():
        return jsonify({"error": "Usuário não encontrado"}), 401

    cursor.execute("SELECT email FROM cadastro WHERE email = ?", (email,))
    if cursor.fetchone():
        return jsonify({"error": "Esse email já está sendo usado! "}), 401


    if senha and not validar_senha(senha):
        return jsonify({"error": "A senha deve atender aos critérios exigidos."}), 401

    senha_hash = generate_password_hash(senha).decode('utf-8') if senha else None
    cursor.execute("UPDATE cadastro SET nome = ?, cpf = ?, data_nascimento = ?, email = ?, cidade = ?, senha = COALESCE(?, senha) WHERE id_cadastro = ?",
                   (nome, cpf, data_nascimento, email, cidade, senha_hash, id))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Usuário atualizado com sucesso!'})
#========================================================================================================================================
tentativas_login = 0
@app.route('/login', methods=['POST'])
def login():
    global tentativas_login
    data = request.get_json()
    email, senha = data.get('email'), data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Email e senha são obrigatórios"}), 400

    cursor = con.cursor()
    cursor.execute("SELECT senha, tentativas_login, ativo, cargo, id_cadastro, nome, cpf, data_nascimento, cidade, email FROM cadastro WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        return jsonify({"error": "Email não encontrado"}), 404

    email = usuario[9]

    if not usuario[2]:
        return jsonify({"error": "Conta inativa. Entre em contato com o suporte."}), 403

    senha_hash = usuario[0]
    id_usuario = usuario[4]

    if check_password_hash(senha_hash, senha):
        cursor.execute("UPDATE cadastro SET tentativas_login = 0 WHERE email = ?", (email,))
        con.commit()
        cursor.close()
        token = generate_token(id_usuario, email)

        return jsonify({
                        "mensagem": "Login realizado com sucesso!",
                        "id_cadastro": usuario[4],
                        "nome": usuario[5],
                        "cpf": usuario[6],
                        "data_nascimento": usuario[7],
                        "email": usuario[9],
                        "cidade": usuario[8],
                        "cargo": usuario[3],
                        'token': token}), 200
    else:
        if usuario[3] != 'ADM':
            tentativas_login += 1
            if tentativas_login == 3:
                cursor.execute("UPDATE cadastro SET tentativas_login = ?, ativo = ? WHERE email = ?", (tentativas_login, False, email)),
                con.commit()
                cursor.close()
                return jsonify({"error": "Conta bloqueada após 3 tentativas de login inválidas. Sua conta foi inativada."}), 401
            return jsonify({"mensagem": tentativas_login}), 401

    cursor.execute("UPDATE cadastro SET tentativas_login = ?, senha = ? WHERE email = ?", (tentativas_login, senha, email))
    con.commit()
    cursor.close()

    return jsonify({"error": f"Senha inválida. Tentativa {tentativas_login} de 3."}), 401
#========================================================================================================================================
@app.route('/filme', methods=['GET'])
def listar_filmes():
    cur = None
    try:
        cur = con.cursor()
        query = """
            SELECT id_cadastrof, titulo, sinopse, genero, duracao, 
                   diretor, elenco, classificacao, link 
            FROM cadastro_filme 
            WHERE status IS NULL
        """
        cur.execute(query)
        filmes = cur.fetchall()

        filmes_lista = []
        for filme in filmes:
            filmes_lista.append({
                'id_cadastrof': filme[0],
                'titulo': filme[1],
                'sinopse': filme[2],
                'genero': filme[3],
                'duracao': filme[4],
                'diretor': filme[5],
                'elenco': filme[6],
                'classificacao': filme[7],
                'imagem': f"static/uploads/cadastro_filme/{filme[0]}.jpeg",
                'link': filme[8]
            })

        return jsonify({'mensagem': 'Lista de filmes', 'cadastro': filmes_lista})

    except Exception as e:
        return jsonify({'erro': str(e)}), 500

    finally:
        if cur:
            cur.close()
@app.route('/filme_imagem', methods=['POST'])
def filme_imagem():
    # Obtém o token de autenticação do cabeçalho da requisição
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
     # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Obtém os dados do formulário enviados na requisição
    titulo = request.form.get('titulo')
    sinopse = request.form.get('sinopse')
    genero = request.form.get('genero')
    duracao = request.form.get('duracao')
    diretor = request.form.get('diretor')
    elenco = request.form.get('elenco')
    classificacao = request.form.get('classificacao')
    status = request.form.get('status')
    imagem = request.files.get('imagem')
    banner = request.files.get('banner')
    link = request.files.get('link')

    # Conecta ao banco de dados e verifica se o filme já existe
    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM cadastro_filme WHERE TITULO = ?", (titulo,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Filme já cadastrado"}), 400

    # Insere os dados do filme no banco e retorna o ID gerado
    cursor.execute(
    "INSERT INTO cadastro_filme (TITULO, SINOPSE, GENERO, DURACAO, DIRETOR, ELENCO, CLASSIFICACAO, link, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ID_CADASTROF",
    (titulo, sinopse, genero, duracao, diretor, elenco, classificacao, link, status)
    )
    cadastrof_id = cursor.fetchone()[0]
    con.commit()

    imagem_path = None
    banner_path = None

    # Salva a imagem do filme, se fornecida
    if imagem:
        nome_imagem = f"{cadastrof_id}.jpeg" #Define o nome do arquivo da imagem usando o ID do cadastro
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "cadastro_filme") #Destino de onde a imagem esta salva
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    # Salva a imagem do banner, se fornecida
    if banner:
        nome_imagem = f"Banner - {cadastrof_id}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "cadastro_filme")

        #Cria a pasta de destino caso ela não exista
        os.makedirs(pasta_destino, exist_ok=True)
        banner_path = os.path.join(pasta_destino, nome_imagem)
        banner.save(banner_path)

    # Fecha o cursor do banco de dados
    cursor.close()

    # Retorna uma resposta JSON confirmando o cadastro do filme
    return jsonify({
        'message': "Filmes cadastrado com sucesso!",
        'cadastro_filme ': {
            'id': cadastrof_id,
            'titulo': titulo,
            'sinopse': sinopse,
            'genero': genero,
            'duracao': duracao,
            'diretor': diretor,
            'elenco': elenco,
            'classificacao': classificacao,
            'status': status,
            'imagem_path': imagem_path,
            'banner_path': banner_path,
            'link': link
        }
    }), 201
@app.route('/filme_edit_dados/<int:id>', methods=['PUT'])
def atualizar_dados_filme(id):

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    data = request.get_json()

    titulo = data.get('titulo')
    sinopse = data.get('sinopse')
    genero = data.get('genero')
    duracao = data.get('duracao')
    diretor = data.get('diretor')
    elenco = data.get('elenco')
    status = data.get('status')
    classificacao = data.get('classificacao')
    link = data.get('link')


    print(titulo)

    cursor = con.cursor()
    cursor.execute("SELECT id_cadastrof FROM cadastro_filme WHERE id_cadastrof = ?", (id,))
    if not cursor.fetchone():
        return jsonify({"error": "Filme não encontrado"})

    cursor.execute("""UPDATE cadastro_filme SET titulo = ?, sinopse = ?, genero = ?, duracao = ?, diretor = ?, elenco = ?, classificacao = ? ,  status = ?, link = ? WHERE id_cadastrof = ? """, (titulo, sinopse, genero, duracao, diretor, elenco, classificacao, status, link, id))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Dados do filme atualizados com sucesso!'})
@app.route('/filme_edit_imagem/<int:id>', methods=['PUT'])
def atualizar_imagem_filme(id):

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    imagem = request.files.get('imagem')  # Obtém o arquivo de imagem enviado na requisição, usando o nome 'imagem' do campo de arquivo.
    banner = request.files.get('banner')

    cursor = con.cursor()  # Cria um cursor para executar comandos SQL no banco de dados.
    cursor.execute("SELECT id_cadastrof FROM cadastro_filme WHERE id_cadastrof = ?", (id,))
    if not cursor.fetchone():   # Se não houver nenhum filme com esse 'id', retorna um erro.
        return jsonify({"error": "Filme não encontrado"})

    pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "cadastro_filme")  # Define o caminho da pasta de destino para salvar as imagens, usando a configuração 'UPLOAD_FOLDER' do aplicativo.
    os.makedirs(pasta_destino, exist_ok=True) # Cria a pasta de destino se ela não existir, garantindo que o diretório seja criado.

    if imagem:
        imagem_path = os.path.join(pasta_destino, f"{id}.jpeg") # Define o caminho onde a imagem será salva, usando o 'id' do filme e o formato '.jpeg'.
        imagem.save(imagem_path) # Salva o arquivo de imagem no caminho definido

    if banner:
        banner_path = os.path.join(pasta_destino, f"Banner - {id}.jpeg")  # Define o caminho onde o banner será salvo, utilizando o 'id' do filme e o prefixo "Banner - ".
        banner.save(banner_path)

    cursor.close()
    return jsonify({'mensagem': 'Imagem e/ou banner atualizados com sucesso!'})
@app.route('/deletar/<int:id>', methods=['DELETE'])
def inativar_filme(id):
    cursor = con.cursor()

    # Verifica se o filme existe
    cursor.execute("SELECT 1 FROM CADASTRO_FILME WHERE ID_CADASTROF = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Filme não encontrado"}), 404

    # Inativa o filme (STATUS = 1)
    cursor.execute("UPDATE CADASTRO_FILME SET STATUS = 1 WHERE ID_CADASTROF = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Filme inativado com sucesso!",
        'id_cadastrof': id
    })
#========================================================================================================================================
@app.route('/usuarios/lista', methods=['GET'])
def lista_usuarios():

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

        # Verifica se o usuário é ADM
    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    # Criação do cursor para realizar a consulta
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, cpf, email, CASE cidade WHEN 1 THEN 'Birigui' WHEN 2 THEN 'Araçatuba' END cidade, ativo, cargo FROM cadastro")  # Modifiquei para pegar os dados desejados
    usuarios = cur.fetchall()  # Obtendo todos os registros

    # Fechando o cursor após a consulta
    cur.close()

    # Estruturando os dados para retornar / listagem de usuarios
    usuarios_lista = [{
        'id': usuario[0],
        'nome': usuario[1],
        'cpf': usuario[2],
        'email': usuario[3],
        'cidade': usuario[4],
        'ativo': 'Ativo' if usuario[5] else 'Inativo',
        'cargo': usuario[6]
    } for usuario in usuarios]

    # Retorna a lista de usuários no formato JSON
    return jsonify({'mensagem': 'Lista de usuários', 'usuarios': usuarios_lista})
@app.route('/usuarios/editar/<int:id_usuario>', methods=['PUT'])
def editar_usuario(id_usuario):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_token = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 401

    # Verifica se o usuário é ADM
    if not verifica_adm(id_usuario_token):
        return jsonify({'message': 'Acesso negado. Usuário não é administrador.'}), 403

    # Dados recebidos do front-end para atualizar
    dados = request.get_json()

    # Abre conexão com o banco
    cur = con.cursor()
    cur.execute("SELECT email, nome, cidade, cargo FROM cadastro WHERE id_cadastro = ?", (id_usuario,))
    usuario = cur.fetchone()
    cur.close()

    return jsonify({'message': 'Usuário não encontrado'}), 404

    email_armazenado, nome_armazenado, cidade_armazenado, cargo_armazenado = usuario

    # Validação de dados
    nome = dados.get('nome', nome_armazenado)
    cpf = dados.get('cpf')
    email = dados.get('email', email_armazenado)
    cidade = dados.get('cidade', cidade_armazenado)
    ativo = dados.get('ativo')
    cargo = dados.get('cargo', cargo_armazenado)

    # Converte o valor de 'ativo' para 1 ou 0
    if ativo == "Ativo":
        ativo = 1
    elif ativo == ("Inat"
                   "ivo"):
        ativo = 0
    elif ativo is not None:
        return jsonify({'message': 'Valor de "ativo" inválido'}), 400  # Retorna erro se o valor não for esperado

    # Atualiza o usuário no banco de dados
    cur.execute("""
        UPDATE cadastro 
        SET nome = ?, cpf = ?, email = ?, cidade = ?, ativo = ?, cargo = ? 
        WHERE id_cadastro = ?
    """, (nome, cpf, email, cidade, ativo, cargo, id_usuario))
    con.commit()
    cur.close()

    #retorna a mensagem com os dados atualizados
    return jsonify({
        'message': 'Usuário atualizado com sucesso',
        'Editar_usuario': {
            'id': id_usuario,
            'nome': nome,
            'cpf': cpf,
            'email': email,
            'cidade': cidade,
            'cargo': cargo,
            'ativo': ativo
        }
    }), 200
#========================================================================================================================================
@app.route('/promocao', methods=['GET'])
def listar_promocao():
    cur = con.cursor()
    # Executa uma consulta SQL que seleciona as informações da tabela 'promocao'.
    cur.execute("SELECT id_promo, titulopromo, duracaopromo, generopromo , duracaopromo FROM promocao")

    promocao = cur.fetchall()
    cur.close()

    capapromo = None

    promocao_lista = [{      # Cria uma lista de dicionários com os resultados da consulta.
        'id_promo': promocao[0],
        'titulo': promocao[1],
        'duracaopromo': promocao[2],
        'generopromo': promocao[3],
        'descricaopromo': promocao[4],
        'capapromo': f"static/uploads/promocao/{promocao[0]}.jpeg"   # Gera o caminho para a capa da promoção, usando o ID da promoção e o formato .jpeg.

    } for promocao in promocao]

    return jsonify({'mensagem': 'Lista de promoção', 'promocao': promocao_lista})
@app.route('/promocao/add', methods=['POST'])
def adicionar_promocao():

    # Verifica o token
    token = request.headers.get('Authorization')
    print("Token recebido:", token)
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
        print("ID do usuário no token:", id_usuario)
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401


    # Obtém os dados da requisição
    titulopromo = request.form.get('titulopromo')
    duracaopromo = request.form.get('duracaopromo')
    generopromo = request.form.get('generopromo')
    descricaopromo = request.form.get('descricaopromo')
    capapromo = request.files.get('capapromo')
    print("Dados recebidos:", titulopromo, duracaopromo, generopromo, descricaopromo)

    # Verifica se todos os campos estão preenchidos
    if not all([titulopromo, duracaopromo, generopromo, descricaopromo]):
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    # Verifica se a promoção já está cadastrada
    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM promocao WHERE TITULOPROMO = ?", (titulopromo,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Promoção já cadastrada"}), 400

    # Insere a promoção no banco de dados
    cursor.execute("""
        INSERT INTO promocao (titulopromo, duracaopromo, generopromo, descricaopromo)
        VALUES (?, ?, ?, ?)
        RETURNING id_promo
    """, (titulopromo, duracaopromo, generopromo, descricaopromo))

    id_promo = cursor.fetchone()[0]  # Obtém o ID gerado
    con.commit()
    cursor.close()

    capapromo_path = None
    if capapromo:
        nome_imagem = f"{id_promo}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "promocao")
        os.makedirs(pasta_destino, exist_ok=True)
        capapromo_path = os.path.join(pasta_destino, nome_imagem)
        capapromo.save(capapromo_path)

    return jsonify({
        'mensagem': 'Promoção cadastrada com sucesso!',
        'promocao': {
            'id': id_promo,
            'titulopromo': titulopromo,
            'duracaopromo': duracaopromo,
            'generopromo': generopromo,
            'descricaopromo': descricaopromo,
            'capapromo_path': capapromo_path
        }
    }), 201
@app.route('/promocao_edit_dados/<int:id_promo>', methods=['PUT'])
def editar_promocao(id_promo):  # <- Corrigido: era id_usuario

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    # Dados do formulário
    data = request.get_json()
    titulopromo = data.get('titulopromo')
    duracaopromo = data.get('duracaopromo')
    generopromo = data.get('generopromo')
    descricaopromo = data.get('descricaopromo')

    cursor = con.cursor()

    # <- Corrigido: trocado de 'id' para 'id_promo'
    cursor.execute("SELECT id_promo FROM promocao WHERE id_promo = ?", (id_promo,))
    if not cursor.fetchone():
        return jsonify({"error": "Promoção não encontrada"})

    # <- Corrigido: trocado de 'id' para 'id_promo'
    cursor.execute("""
        UPDATE promocao 
        SET titulopromo = ?, duracaopromo = ?, generopromo = ?, descricaopromo = ? 
        WHERE id_promo = ?
    """, (titulopromo, duracaopromo, generopromo, descricaopromo, id_promo))

    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Promoção atualizada com sucesso!'})
@app.route('/promo_edit_imagem/<int:id>', methods=['PUT'])
def atualizar_imagem_promo(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Verifica se o usuário é administrador
    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 403

    imagem = request.files.get('imagem')  # Ex: imagem da capa

    cursor = con.cursor()
    cursor.execute("SELECT id_promo FROM promocao WHERE id_promo = ?", (id,))
    if not cursor.fetchone():
        return jsonify({"error": "Promoção não encontrada"}), 404

    pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "promocao")
    os.makedirs(pasta_destino, exist_ok=True)

    if imagem:
        imagem_path = os.path.join(pasta_destino, f"{id}.jpeg")
        imagem.save(imagem_path)

    cursor.close()
    return jsonify({'mensagem': 'Imagem da promoção atualizados com sucesso!'})
@app.route('/promocao/delete/<int:id_promo>', methods=['DELETE'])
def deletar_promocao(id_promo):
    # Verifica o token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Verifica se a promoção existe
    cursor.execute("SELECT id_promo FROM promocao WHERE id_promo = ?", (id_promo,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'mensagem': 'Promoção não encontrada'}), 404

    # Deleta a promoção do banco de dados
    cursor.execute("DELETE FROM promocao WHERE id_promo = ?", (id_promo,))
    con.commit()
    cursor.close()

    # Remove a imagem da capa se existir
    capa_path = os.path.join(app.config['UPLOAD_FOLDER'], "promocao", f"{id_promo}.jpeg")
    if os.path.exists(capa_path):
        os.remove(capa_path)

    return jsonify({'mensagem': f'Promoção com ID {id_promo} deletada com sucesso'}), 200
#========================================================================================================================================
@app.route('/salas', methods=['GET'])
def get_salas():

    # Consulta para obter todas as salas do banco de dados
    cur = con.cursor()
    cur.execute("SELECT id_sala, nome_sala, descricao, capacidade FROM salas")  # Supondo que a tabela 'salas' tem esses campos
    salas = cur.fetchall()  #fetchall() recupera todos os resultados da consulta SQL executada.
    cur.close()

    # Formatação dos dados em um formato de resposta JSON
    #Essa lista de dicionários (cada dicionário representa uma sala) é atribuída à variável salas_lista
    salas_lista = [{
        'id_sala': sala[0],
        'nome': sala[1],
        'descricao': sala[2],
        'capacidade': sala[3]
    } for sala in salas]

    return jsonify({'mensagem': 'Lista de salas', 'salas': salas_lista})    # Retorna uma resposta JSON com a mensagem 'Lista de salas' e a lista de salas formatada.
@app.route('/salas/add', methods=['POST'])
def criar_sala():

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

        # Verifica se o usuário é ADM
    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    # Obtém os dados da requisição
    data = request.get_json()
    nome_sala = data.get('nome_sala')
    descricao = data.get('descricao')
    capacidade = data.get('capacidade')

    # Valida os dados
    if not nome_sala or not capacidade:
        return jsonify({"error": "Nome da sala e capacidade são obrigatórios!"}), 400   # Retorna um erro 400 se algum dos dados obrigatórios estiver faltando.

    # Insere a nova sala no banco de dados
    cursor = con.cursor()
    cursor.execute("INSERT INTO salas (nome_sala, descricao, capacidade) VALUES (?, ?, ?)", (nome_sala, descricao, capacidade))
    con.commit()
    cursor.close()

    return jsonify({"mensagem": "Sala criada com sucesso!"}), 201   # Retorna uma resposta JSON com a mensagem 'Sala criada com sucesso!' e o código de status 201 (criado), indicando que a sala foi inserida com sucesso no banco de dados.
#========================================================================================================================================
@app.route('/sessao/<int:id>', methods=['GET'])
def analizar_sessao(id):
   # bloquear_sessoes_vencidas()

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cur = con.cursor()

    query = """
        SELECT 
            s.id_sessao,
            s.id_sala,
            s.id_cadastrof,
            s.datasessao,
            s.valor_assento,
            sal.nome_sala,
            COUNT(DISTINCT a.id_assento) - 
            COALESCE((
                SELECT COUNT(ra.id_assento)
                FROM reserva_assentos ra
                JOIN reserva r ON ra.id_reserva = r.id_reserva
                WHERE r.id_sessao = s.id_sessao
            ), 0) AS assentos_disponiveis
        FROM sessao s
        left JOIN salas sal ON s.id_sala = sal.id_sala
        left JOIN ASSENTOS a ON a.id_sala = s.id_sala
        WHERE s.status = 0 AND s.id_cadastrof = ?
        GROUP BY s.id_sessao, s.id_sala, s.id_cadastrof, s.datasessao, s.valor_assento, sal.nome_sala
    """

    cur.execute(query, (id,))
    resultados = cur.fetchall()
    cur.close()

    if not resultados:
        return jsonify({'mensagem': 'Nenhuma sessão encontrada para este filme.'}), 404

    sessao_lista = [{
        'id_sessao': linha[0],
        'id_sala': linha[1],
        'id_cadastrof': linha[2],
        'datasessao': linha[3].strftime('%d/%m/%Y às %H:%M'),
        'valor_assento': linha[4],
        'nome_sala': linha[5],
        'assentos_disponiveis': linha[6]
    } for linha in resultados]

    return jsonify({
        'mensagem': 'Sessões encontradas com sucesso.',
        'sessoes': sessao_lista
    }), 200
@app.route('/sessao/add', methods=['POST'])
def criar_sessao():
    token = request.headers.get('Authorization')  # Busca o token de autenticação

    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 403

    data = request.get_json()
    id_sala = data.get('id_sala')
    id_cadastrof = data.get('id_cadastrof')
    datasessao = data.get('datasessao')
    valor_assento = data.get('valor_assento')

    if not id_sala or not id_cadastrof or not datasessao:
        return jsonify({"error": "ID da sala, ID do filme e data da sessão são obrigatórios!"}), 400

    try:
        data_sessao_datetime = datetime.strptime(datasessao, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return jsonify({"error": "Formato de data inválido! Use: YYYY-MM-DD HH:MM:SS"}), 400

    if data_sessao_datetime <= datetime.now():
        return jsonify({"error": "Não é possível criar uma sessão com data e hora no passado!"}), 400

    cursor = con.cursor()

    # Verifica se a sala existe
    cursor.execute("SELECT 1 FROM salas WHERE id_sala = ?", (id_sala,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Sala não encontrada!"}), 404

    # Verifica se o filme existe e obtém a duração
    cursor.execute("SELECT duracao FROM cadastro_filme WHERE id_cadastrof = ?", (id_cadastrof,))
    resultado = cursor.fetchone()
    if not resultado:
        cursor.close()
        return jsonify({"error": "Filme não encontrado!"}), 404

    duracao_filme = resultado[0]  # duração em minutos

    # Verifica conflito de horário na sala com base na duração do filme
    cursor.execute("""
        SELECT 1
        FROM sessao se
        INNER JOIN cadastro_filme f ON f.id_cadastrof = se.id_cadastrof
        WHERE se.id_sala = ?
          AND (
              (? < DATEADD(MINUTE, f.duracao, se.datasessao)) AND
              (DATEADD(MINUTE, ?, ?) > se.datasessao)
          )
    """, (id_sala, datasessao, duracao_filme, datasessao))

    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Sala indisponível para o horário e duração informados!"}), 400

    # Insere a nova sessão
    cursor.execute("""
        INSERT INTO sessao (id_sala, id_cadastrof, datasessao, status, valor_assento)
        VALUES (?, ?, ?, ?, ?)
    """, (id_sala, id_cadastrof, datasessao, 0, valor_assento))
    con.commit()
    cursor.close()

   # bloquear_sessoes_vencidas()  # Atualiza sessões expiradas

    return jsonify({"mensagem": "Sessão criada com sucesso!"}), 201
#========================================================================================================================================
@app.route('/assentos', methods=['GET'])
def analizar_assentos():

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    # Remove o prefixo 'Bearer' do token, se existir
    token = remover_bearer(token)

    try:
        # Decodifica o token para obter os dados do usuário
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

        # Verifica se o usuário é ADM
    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    cur = con.cursor()
    cur.execute("SELECT id_assento, id_sala, coluna, numero_assento FROM assentos")   #seleciona os seguintes campos da tabela 'assentos'
    assentos = cur.fetchall()
    cur.close()

    # Abaixo, cria uma lista de dicionários, onde cada dicionário representa um assento com os dados obtidos.
    assentos_lista = [{
        'id_sessao': assentos[0],
        'id_sala': assentos[1],
        'id_cadastrof': assentos[2],
        'data_hora': assentos[3]
    } for assentos in assentos]

    return jsonify({'mensagem': 'Lista de assentos', 'assentos': assentos_lista})   # Retorna a resposta JSON com a chave 'mensagem' e a chave 'assentos', que contém os dados dos assentos.
#========================================================================================================================================
@app.route('/reservar', methods=['POST'])
def reservar_assentos():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
        email = payload['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    data = request.get_json()
    id_sessao = data.get('id_sessao')
    id_assentos = data.get('id_assento')  # lista de assentos
    id_cadastro = data.get('id_cadastro')

    if not isinstance(id_assentos, list):
        return jsonify({'mensagem': 'id_assento deve ser uma lista de assentos'}), 400

    cursor = con.cursor()

    # Verifica se algum dos assentos já está reservado na mesma sessão
    for id_assento in id_assentos:
        cursor.execute("""
            SELECT 1 FROM RESERVA_ASSENTOS ra
            JOIN RESERVA r ON r.ID_RESERVA = ra.ID_RESERVA
            WHERE r.ID_SESSAO = ? AND ra.ID_ASSENTO = ?
        """, (id_sessao, id_assento))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"erro": f"O assento {id_assento} já está reservado nessa sessão"}), 400

    # Cria uma nova reserva e obtém o ID gerado
    cursor.execute("""
        INSERT INTO RESERVA (ID_SESSAO, ID_CADASTRO, STATUS)
        VALUES (?, ?, ?)
        RETURNING ID_RESERVA
    """, (id_sessao, id_cadastro, 'RESERVADO'))
    id_reserva = cursor.fetchone()[0]

    # Insere os assentos vinculados à reserva
    for id_assento in id_assentos:
        cursor.execute("""
            INSERT INTO RESERVA_ASSENTOS (ID_RESERVA, ID_ASSENTO)
            VALUES (?, ?)
        """, (id_reserva, id_assento))

    con.commit()
    cursor.close()

    # Recupera o nome do usuário
    cursor = con.cursor()
    cursor.execute("SELECT nome FROM cadastro WHERE id_cadastro = ?", (id_cadastro,))
    nome = cursor.fetchone()[0]
    cursor.close()

    # Dados da sessão
    cursor = con.cursor()
    cursor.execute("""
        SELECT s.DATASESSAO, cf.TITULO, sa.NOME_SALA 
        FROM sessao s 
        LEFT JOIN CADASTRO_FILME cf ON cf.ID_CADASTROF = s.ID_CADASTROF 
        LEFT JOIN salas sa ON sa.ID_SALA = s.ID_SALA 
        WHERE s.ID_SESSAO = ?
    """, (id_sessao,))
    dados = cursor.fetchone()
    data_sessao = dados[0]
    titulo = dados[1]
    nome_sala = dados[2]
    cursor.close()

    # Formata os assentos
    cursor = con.cursor()
    format_ids = ','.join('?' for _ in id_assentos)
    query = f"""
        SELECT LIST(a.COLUNA || a.NUMERO_ASSENTO, ', ') 
        FROM ASSENTOS a 
        WHERE a.ID_ASSENTO IN ({format_ids})
    """
    cursor.execute(query, id_assentos)
    assentos = cursor.fetchone()[0]
    cursor.close()

    # Busca o valor do assento da sessão
    cursor = con.cursor()
    cursor.execute("""
        SELECT VALOR_ASSENTO FROM sessao WHERE ID_SESSAO = ?
    """, (id_sessao,))
    valor_assento = cursor.fetchone()[0]
    cursor.close()

    if valor_assento is None:
        return jsonify({"erro": "Sessão sem valor de assento definido"}), 400

    quantidade_assentos = len(id_assentos)
    valor_total = valor_assento * quantidade_assentos

    # Atualiza o valor total da reserva
    cursor = con.cursor()
    cursor.execute("""
        UPDATE RESERVA SET VALOR_TOTAL = ? WHERE ID_RESERVA = ?
    """, (valor_total, id_reserva))
    con.commit()
    cursor.close()

    # Formata a data
    data_formatada = data_sessao.strftime('%d/%m/%Y às %H:%M')

    # Geração do QR Code
    nome_arquivo = f'pix_{id_reserva}.png'
    pasta_qrcodes = os.path.join(os.getcwd(), "upload", "qrcodes")
    imgQrCode = os.path.join(pasta_qrcodes, nome_arquivo)

    gerar_qrcode_pix(valor_total, nome_arquivo)


    url = "https://api.imgur.com/3/image"

    headers = {
        "Authorization": "Client-ID f8c69622b39f14b"
    }

    files = {
        "image": open(imgQrCode, "rb")
    }

    data = {
        "type": "image",
        "title": "Simple upload",
        "description": "This is a simple image upload in Imgur"
    }

    response = requests.post(url, headers=headers, files=files, data=data)

    if response.status_code == 200:
        image_link = response.json()["data"]["link"]
        print("Link da imagem:", image_link)

        texto_html = (
            f"<div style='font-family: Arial, sans-serif; color: #fff; max-width: 650px; margin: auto; padding: 30px; background-color: #111; border-radius: 12px; box-shadow: 0 0 15px rgba(255,0,0,0.2);'>"

            # Cabeçalho
            f"<div style='text-align: center;'>"
            f"  <h1 style='color: #e50914;'>🎬 <span style='color: #ffcc00;'>Cinestrelar</span></h1>"
            f"  <p style='font-size: 18px; margin-top: 0; color: #fff;'>A magia do cinema começa aqui!</p>"
            f"</div>"

            f"<hr style='border: none; border-top: 2px solid #e50914; margin: 20px 0;'/>"

            # Saudação
            f"<section>"
            f"  <h2 style='color: #fff;'>👋 Olá, {nome}!</h2>"
            f"  <p style='font-size: 16px;'>Sua sessão foi <strong style='color: #e50914;'>confirmada com sucesso</strong>!</p>"
            f"  <p style='color: #fff;'>Prepare-se para uma experiência cinematográfica inesquecível!</p>"
            f"</section>"

            # Detalhes da Sessão
            f"<section style='margin-top: 30px;'>"
            f"  <h3 style='color: #e50914;'>📌 Detalhes da sua sessão</h3>"
            f"  <div style='background-color: #1c1c1c; border-radius: 10px; padding: 20px; box-shadow: 0 0 5px rgba(255,0,0,0.1); color: #fff;'>"
            f"    <p>🎬 <strong>Filme:</strong> {titulo}</p>"
            f"    <p>🏟️ <strong>Sala:</strong> {nome_sala}</p>"
            f"    <p>💺 <strong>Assento(s):</strong> {assentos}</p>"
            f"    <p>🕒 <strong>Horário:</strong> {data_formatada}</p>"
            f"    <p>💰 <strong>Total:</strong> R$ {valor_total:.2f}</p>"
            f"  </div>"
            f"</section>"

            # QR Code e Pagamento
            f"<section style='margin-top: 30px; text-align: center;'>"
            f"  <h3 style='color: #e50914;'>💳 Pagamento via <span style='color: #ffcc00;'>PIX</span></h3>"
            f"  <p style='font-size: 15px; color: #fff;'>Escaneie o QR Code abaixo para realizar o pagamento:</p>"
            f"  <img src='{image_link}' style='width: 220px; border: 2px solid #e50914; padding: 10px; border-radius: 12px; margin-top: 10px;' />"
            f"</section>"

            # Avisos Importantes
            f"<section style='margin-top: 40px; background-color: #2a2a2a; border-left: 6px solid #e50914; padding: 20px; border-radius: 10px;'>"
            f"  <h3 style='color: #ffcc00;'>⚠️ Avisos importantes</h3>"
            f"  <ul style='font-size: 14px; line-height: 1.6; color: #fff;'>"
            f"    <li>⏰ Chegue pelo menos <strong>15 minutos antes</strong> do horário marcado.</li>"
            f"    <li>🚪 Após o início do filme, a entrada será <strong>restrita</strong>.</li>"
            f"    <li>🧃 O <strong>balcão de lanches</strong> abre 30 minutos antes da sessão.</li>"
            f"    <li>👜 Evite trazer mochilas e bolsas grandes.</li>"
            f"    <li>📵 Mantenha o celular no <strong>modo silencioso</strong>.</li>"
            f"    <li>🪪 Leve um <strong>documento válido</strong> se comprou meia-entrada.</li>"
            f"  </ul>"
            f"</section>"

            # Agradecimento Final
            f"<section style='margin-top: 40px; text-align: center;'>"
            f"  <p style='font-size: 16px; color: #ffcc00;'>🎞️ <strong>Obrigado por escolher o Cinestrelar!</strong></p>"
            f"  <p style='color: #fff;'>Desejamos a você uma excelente sessão!</p>"
            f"  <p style='margin-top: 20px; font-size: 14px; color: #fff;'>Equipe Cinestrelar ✨</p>"
            f"</section>"

            f"</div>"
        )

        try:
            print(f"Enviando e-mail para: {email}")
            enviar_email(email, texto_html)
            print("E-mail enviado com sucesso!")
        except Exception as email_error:
            return jsonify({"erro": f"Erro ao enviar o e-mail: {str(email_error)}"}), 500
    else:
        print("Erro ao fazer upload:", response.status_code)
        print(response.json())

    return jsonify({"mensagem": "Reserva realizada com sucesso!"}), 201
#========================================================================================================================================
def calcula_crc16(payload):    #(CRC16) a função gera esse número com base no conteúdo do payload (os dados que o QR Code vai carregar).
    crc16 = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False)
    crc = crc16(payload.encode('utf-8'))
    return f"{crc:04X}"
def format_tlv(id, value):  #Esse formato é usado para organizar os dados de uma maneira padronizada e fácil de ler. (format_tlv). Basicamente, ela cria uma estrutura de dados onde cada pedaço de informação é precedido por uma tag (um identificador), seguido pelo tamanho dessa informação e, por fim, o valor em si.
    return f"{id}{len(value):02d}{value}"
def gerar_qrcode_pix(valor_total, nome_arquivo):
    try:
        # Formata o valor recebido para duas casas decimais (ex: 50.0 -> "50.00")
        valor_formatado = f"{float(valor_total):.2f}"

        # Cria um cursor para executar comandos SQL no banco de dados
        cursor = con.cursor()

        # Consulta o banco de dados para obter nome, chave PIX e cidade do recebedor
        cursor.execute("SELECT cg.NOME, cg.CHAVE_PIX, cg.CIDADE FROM CONFIG_CINE cg")

        # Recupera o primeiro (e único) resultado da consulta
        resultado = cursor.fetchone()

        # Encerra o uso do cursor
        cursor.close()

        # Se a consulta não retornar dados, lança um erro (não é possível gerar QR sem a chave PIX)
        if not resultado:
            raise ValueError("Chave PIX não encontrada")

        # Atribui os dados retornados às variáveis correspondentes
        nome, chave_pix, cidade = resultado

        # Se o nome estiver presente, trunca para 25 caracteres; senão, usa valor padrão
        nome = nome[:25] if nome else "Recebedor PIX"

        # Trunca a cidade para 15 caracteres, com valor padrão caso esteja ausente
        cidade = cidade[:15] if cidade else "Cidade"

        # Monta as informações da conta do recebedor (formato exigido pelo padrão PIX)
        merchant_account_info = (
                format_tlv("00", "br.gov.bcb.pix") +  # Identificador do domínio PIX
                format_tlv("01", chave_pix)  # Chave PIX do recebedor
        )

        # Cria o campo 26 com os dados de conta do recebedor (obrigatório no QR PIX)
        campo_26 = format_tlv("26", merchant_account_info)

        # Constrói o payload completo do QR Code (exceto o CRC final)
        payload_sem_crc = (
                "000201" +  # Identificador do formato do QR Code (versão 01)
                "010212" +  # Transação do tipo "dinâmica com valor"
                campo_26 +  # Dados da conta do recebedor
                "52040000" +  # Código de categoria do ponto de venda (fixo)
                "5303986" +  # Moeda: BRL (986 = Real Brasileiro)
                format_tlv("54", valor_formatado) +  # Valor da transação
                "5802BR" +  # País de origem (BR = Brasil)
                format_tlv("59", nome) +  # Nome do recebedor
                format_tlv("60", cidade) +  # Cidade do recebedor
                format_tlv("62", format_tlv("05", "***")) +  # Informações adicionais, como referência
                "6304"  # Campo reservado para o CRC16 (será adicionado a seguir)
        )

        # Calcula o CRC16 do payload para garantir integridade do código
        crc = calcula_crc16(payload_sem_crc)

        # Finaliza o payload do QR Code incluindo o CRC calculado
        payload_completo = payload_sem_crc + crc

        # Inicializa o gerador de QR Code com configurações de qualidade
        qr_obj = qrcode.QRCode(
            version=None,  # Deixa a biblioteca definir o tamanho adequado automaticamente
            error_correction=ERROR_CORRECT_H,  # Alta correção de erro (recomendado para pagamentos)
            box_size=10,  # Tamanho dos blocos do QR Code
            border=4  # Tamanho da borda branca em torno do código
        )

        # Adiciona os dados gerados ao QR Code
        qr_obj.add_data(payload_completo)

        # Finaliza a construção do QR Code ajustando ao conteúdo
        qr_obj.make(fit=True)

        # Gera a imagem do QR Code com cores padrão (preto sobre branco)
        qr = qr_obj.make_image(fill_color="black", back_color="white")

        # Define o caminho onde o QR Code será salvo
        pasta_qrcodes = os.path.join(os.getcwd(), "upload", "qrcodes")

        # Garante que o diretório existe (cria se necessário)
        os.makedirs(pasta_qrcodes, exist_ok=True)

        # Se não for fornecido um nome de arquivo, pode-se gerar um automaticamente (comentado aqui)
        if not nome_arquivo:
            arquivos_existentes = [f for f in os.listdir(pasta_qrcodes) if f.startswith("pix_") and f.endswith(".png")]
            numeros_usados = []
            for nome_arq in arquivos_existentes:
                try:
                    num = int(nome_arq.replace("pix_", "").replace(".png", ""))
                    numeros_usados.append(num)
                except ValueError:
                    continue

        # Define o caminho final do arquivo de imagem do QR Code
        caminho_arquivo = os.path.join(pasta_qrcodes, nome_arquivo)

        # Salva o QR Code como imagem PNG
        qr.save(caminho_arquivo)

        # (Opcional) imprime o payload no console, útil para depuração
        print(payload_completo)

        # Retorna o caminho do arquivo e o nome gerado/salvo
        return caminho_arquivo, nome_arquivo

    except Exception as e:
        # Em caso de erro, lança uma exceção com mensagem personalizada
        raise RuntimeError(f"Erro ao gerar QR Code PIX: {str(e)}")
#========================================================================================================================================
@app.route('/sessao/assentos/<int:id_sessao>', methods=['GET'])
def assentos_reservados(id_sessao):
    cur = con.cursor()

    # Buscar os assentos reservados para a sessão
    cur.execute("""
        SELECT a.coluna, a.numero_assento
        FROM assentos a
        JOIN reserva_assentos ra ON ra.id_assento = a.id_assento
        JOIN reserva r ON r.id_reserva = ra.id_reserva
        WHERE r.id_sessao = ?
    """, (id_sessao,))

    assentos = cur.fetchall()
    cur.close()

    if not assentos:
        return jsonify({'mensagem': 'Nenhum assento reservado para esta sessão.'}), 404

    # Exemplo de formatação "B3", "C5" dos assentos
    assentos_formatados = [f"{a[0]}{a[1]}" for a in assentos]

    return jsonify({
        'mensagem': 'Assentos reservados encontrados com sucesso.',
        'assentos_reservados': assentos_formatados
    }), 200
#========================================================================================================================================
@app.route('/admin/historico_reservas', methods=['GET'])
def historico_reservas():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    cur = con.cursor()
    cur.execute("""
        SELECT r.id_sessao, r.id_cadastro, r.valor_total,
               s.id_sala, s.id_cadastrof, s.datasessao, s.valor_assento,
               c.nome AS nome_usuario,
               f.titulo AS titulo_filme,
               sala.nome_sala
        FROM reserva r
        JOIN sessao s ON r.id_sessao = s.id_sessao
        JOIN cadastro c ON r.id_cadastro = c.id_cadastro
        JOIN cadastro_filme f ON s.id_cadastrof = f.id_cadastrof
        JOIN salas sala ON s.id_sala = sala.id_sala
        order by s.datasessao
    """)
    reservas = cur.fetchall()
    cur.close()

    reservas_lista = []
    for reserva in reservas:
        # Formatação da data
        data_sessao_formatada = reserva[5].strftime('%d/%m/%Y %H:%M')

        # Garantindo a ordem certa na resposta JSON
        reservas_lista.append({
            'nome_usuario': reserva[7],  # Nome do usuário
            'titulo_filme': reserva[8],   # Título do filme
            'nome_sala': reserva[9],     # Nome da sala
            'data_sessao': data_sessao_formatada,  # Data da sessão
            'valor_assento': float(reserva[6]),    # Valor do assento
            'valor_total': float(reserva[2]),     # Valor total
            'id_sessao': reserva[0]               # ID da sessão
        })

    return jsonify({'mensagem': 'Histórico de Reservas', 'reservas': reservas_lista})
@app.route('/historico_reservas/<int:id_cadastro>', methods=['GET'])
def historico_reservas_individual(id_cadastro):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_logado = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if id_usuario_logado != id_cadastro and not verifica_adm(id_usuario_logado):
        return jsonify({'mensagem': 'Acesso negado'}), 403

    cur = con.cursor()
    cur.execute("""
        SELECT r.id_sessao, r.id_cadastro, r.valor_total,
               s.id_sala, s.id_cadastrof, s.datasessao, s.valor_assento,
               c.nome AS nome_usuario,
               f.titulo AS titulo_filme,
               sala.nome_sala
        FROM reserva r
        JOIN sessao s ON r.id_sessao = s.id_sessao
        JOIN cadastro c ON r.id_cadastro = c.id_cadastro
        JOIN cadastro_filme f ON s.id_cadastrof = f.id_cadastrof
        JOIN salas sala ON s.id_sala = sala.id_sala
        WHERE r.id_cadastro = ?
        ORDER BY s.datasessao
    """, (id_cadastro,))
    reservas = cur.fetchall()
    cur.close()

    reservas_lista = []
    for reserva in reservas:
        data_sessao_formatada = reserva[5].strftime('%d/%m/%Y %H:%M')

        reservas_lista.append({
            'nome_usuario': reserva[7],
            'titulo_filme': reserva[8],
            'nome_sala': reserva[9],
            'data_sessao': data_sessao_formatada,
            'valor_assento': float(reserva[6]),
            'valor_total': float(reserva[2]),
            'id_sessao': reserva[0]
        })

    return jsonify({'mensagem': 'Histórico de Reservas', 'reservas': reservas_lista})
#========================================================================================================================================
@app.route('/buscar_filme', methods=['GET'])
def buscar_filme():
    titulo_busca = request.args.get('titulo')  # Recebe o título do filme via parâmetro de URL

    if not titulo_busca:
        return jsonify({'mensagem': 'Título não fornecido'}), 400

    cur = con.cursor()
    cur.execute("""
        SELECT f.titulo, f.sinopse, f.id_cadastrof
        FROM cadastro_filme f
        WHERE f.titulo = ?
    """, (titulo_busca,))  # Busca o filme com o título exato

    filme = cur.fetchone()  # Busca apenas um filme (já que é pelo título exato)
    cur.close()

    if not filme:
        return jsonify({'mensagem': 'Filme não encontrado'}), 404

    filme_dict = {
        'titulo': filme[0],
        'sinopse': filme[1],
        'id_filme': filme[2]
    }

    return jsonify({'mensagem': 'Filme encontrado', 'filme': filme_dict})
@app.route('/buscar_sessao', methods=['GET'])
def buscar_sessao():
    # Receber o parâmetro de data
    data_sessao = request.args.get('data_sessao')

    if not data_sessao:
        return jsonify({'mensagem': 'Data não fornecida'}), 400

    try:
        # Converter a data recebida para o formato adequado para consulta (YYYY-MM-DD)
        data_sessao_formatada = datetime.strptime(data_sessao, '%d/%m/%Y').date()

    except ValueError:
        return jsonify({'mensagem': 'Formato de data inválido. Use dd/mm/aaaa.'}), 400

    cur = con.cursor()

    # Ajuste para comparar data ignorando a hora
    cur.execute("""
        SELECT s.id_sessao, s.id_sala, s.id_cadastrof, s.datasessao, s.status, s.valor_assento
        FROM sessao s
        WHERE CAST(s.datasessao AS DATE) = ? AND s.status = 0
    """, (data_sessao_formatada,))

    sessoes = cur.fetchall()
    cur.close()

    if not sessoes:
        return jsonify({'mensagem': 'Nenhuma sessão encontrada para a data informada.'}), 404

    sessoes_lista = [{
        'id_sessao': sessao[0],
        'id_sala': sessao[1],
        'id_cadastrof': sessao[2],
        'data_sessao': sessao[3].strftime('%d/%m/%Y %H:%M'),
        'status': sessao[4],
        'valor_assento': float(sessao[5])
    } for sessao in sessoes]

    return jsonify({'mensagem': 'Sessões encontradas', 'sessoes': sessoes_lista})
#========================================================================================================================================
@app.route('/admin/vendas_por_sessao', methods=['GET'])
def vendas_por_sessao():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    cur = con.cursor()
    cur.execute("""
        SELECT 
            s.ID_SESSAO,
            f.TITULO,
            COUNT(ra.ID_ASSENTO) AS total_vendas
        FROM 
            sessao s
        LEFT JOIN 
            reserva r ON s.ID_SESSAO = r.ID_SESSAO
        LEFT JOIN 
            reserva_assentos ra ON r.ID_RESERVA = ra.ID_RESERVA
        LEFT JOIN 
            cadastro_filme f ON s.ID_CADASTROF = f.ID_CADASTROF
        GROUP BY 
            s.ID_SESSAO, f.TITULO
        ORDER BY 
            f.TITULO
    """)
    resultados = cur.fetchall()
    cur.close()

    vendas_por_sessao = []
    for linha in resultados:
        vendas_por_sessao.append({
            'id_sessao': linha[0],
            'titulo_filme': linha[1],
            'total_vendas': linha[2]
        })

    return jsonify({
        'mensagem': 'Total de vendas por sessão',
        'vendas': vendas_por_sessao
    })
@app.route('/total_ingressos_filmes', methods=['GET'])
def total_ingressos_filmes():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if not verifica_adm(id_usuario):
        return jsonify({'mensagem': 'Acesso negado. Usuário não é administrador.'}), 401

    cur = con.cursor()
    cur.execute("""
        SELECT COUNT(*) 
        FROM reserva_assentos
    """)
    resultado = cur.fetchone()
    cur.close()

    total_ingressos = resultado[0] if resultado else 0

    return jsonify({
        'mensagem': 'Total de ingressos vendidos para todos os filmes',
        'total_ingressos': total_ingressos
    })
@app.route('/top_filmes', methods=['GET'])
def top_filmes():
    try:
        query = """
            SELECT upper(COALESCE(cf.TITULO, '')), 
                   cf.ID_CADASTROF, 
                   r.VALOR_TOTAL,
                   (SELECT count(*) FROM RESERVA_ASSENTOS ra
                   WHERE ra.ID_RESERVA = r.id_reserva)
            FROM RESERVA r
            LEFT JOIN SESSAO s ON s.ID_SESSAO = r.ID_SESSAO
            LEFT JOIN CADASTRO_FILME cf ON cf.ID_CADASTROF = s.ID_CADASTROF
        """

        cursor = con.cursor()
        cursor.execute(query)
        filmes = cursor.fetchall()

        # Criando um dicionário para armazenar a soma dos valores por título
        filmes_soma = {}
        total_ingressos = {}

        # Percorrendo os resultados e somando os valores
        for filme in filmes:
            titulo = filme[0]
            valor_total = filme[2]
            qtd_ingressos = filme[3]
            if titulo in filmes_soma:
                filmes_soma[titulo] += valor_total
                total_ingressos[titulo] += qtd_ingressos
            else:
                filmes_soma[titulo] = valor_total
                total_ingressos[titulo] = qtd_ingressos

        filmes_list = []
        for titulo in filmes_soma:
            filmes_list.append({
                "titulo": titulo,
                "bilheteria": filmes_soma[titulo],
                "ingressos": total_ingressos[titulo]
            })

        # Ordena os filmes pela quantidade de ingressos (do maior para o menor)
        filmes_list.sort(key=lambda x: x["ingressos"], reverse=True)

        cursor.close()

        return jsonify(filmes_list)

    except Exception as e:
        print(f"Erro: {e}")
        return jsonify({"erro": "Ocorreu um erro ao buscar os filmes"}), 500
#========================================================================================================================================
@app.route('/esqueci-senha', methods=['POST'])
def esqueci_senha():
    email = request.json.get('email')

    if not email:
        return jsonify({"error": "E-mail é obrigatório"}), 400

    cursor = con.cursor()
    cursor.execute("SELECT id_cadastro, nome FROM CADASTRO WHERE EMAIL = ?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return jsonify({"error": "E-mail não encontrado"}), 404

    nome_usuario = user[1]
    codigo = random.randint(100000, 999999)

    cursor.execute("""
        UPDATE CADASTRO 
        SET CODIGO_RECUPERACAO = ?, VALIDADE_CODIGO = CURRENT_TIMESTAMP + 1
        WHERE EMAIL = ?
    """, (codigo, email))
    con.commit()
    cursor.close()

    # Corpo HTML do e-mail com estilo e nome do usuário
    html_corpo = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #111; padding: 20px; color: #fff;">
        <div style="max-width: 600px; margin: auto; background-color: #1c1c1c; padding: 30px; border-radius: 10px; border: 2px solid #e60000;">
            <h2 style="color: #e60000; text-align: center;">🎬 Recuperação de Senha - Cinestrelar</h2>
            <p>Olá, <strong style="color: #fff;">{nome_usuario}</strong>,</p>
            <p>Recebemos uma solicitação para redefinir sua senha. Aqui está o código de verificação:</p>
            <div style="text-align: center; margin: 30px 0;">
                <h1 style="font-size: 48px; color: #e60000; letter-spacing: 4px;">{codigo}</h1>
            </div>
            <p>Este código é válido por <strong>1 hora</strong>.</p>
            <p>Se você não solicitou essa recuperação, apenas ignore este e-mail.</p>
            <br>
            <p style="color: #ccc;">Atenciosamente,<br><strong style="color: #fff;">Equipe Cinestrelar ⚫🔴</strong></p>
        </div>
    </body>
    </html>
    """

    try:
        enviar_email(email, html_corpo)
        return jsonify({"message": "Código enviado para o e-mail com sucesso!"})
    except Exception as e:
        return jsonify({"error": f"Falha ao enviar e-mail: {str(e)}"}), 500
@app.route('/validar-codigo', methods=['POST'])
def validar_codigo():
    data = request.json
    email = data.get('email')
    codigo = data.get('codigo')

    if not email or not codigo:
        return jsonify({"error": "Email e código são obrigatórios."}), 400

    cursor = con.cursor()
    cursor.execute("SELECT CODIGO_RECUPERACAO, VALIDADE_CODIGO FROM CADASTRO WHERE EMAIL = ?", (email,))
    resultado = cursor.fetchone()

    if not resultado:
        cursor.close()
        return jsonify({"error": "E-mail não encontrado."}), 404

    codigo_banco, validade = resultado

    if codigo_banco is None or validade is None:
        cursor.close()
        return jsonify({"error": "Nenhum código de recuperação foi gerado para este e-mail."}), 400

    if codigo != codigo_banco:
        cursor.close()
        return jsonify({"error": "Código inválido."}), 400

    now = datetime.now()

    if now > validade:
        cursor.close()
        return jsonify({"error": "Código expirado."}), 400

    cursor.execute('''
        UPDATE CADASTRO
        SET TROCAR_SENHA = TRUE
        WHERE EMAIL = ?
    ''', (email,))

    con.commit()
    cursor.close()

    return jsonify({"message": "Código validado com sucesso!"})
@app.route('/trocar-senha', methods=['PUT'])
def trocar_senha():
    data = request.get_json()

    email = data.get('email')
    nova_senha = data.get('nova_senha')

    cursor = con.cursor()

    cursor.execute('''
        SELECT TROCAR_SENHA 
        FROM CADASTRO
        WHERE EMAIL = ?
    ''', (email,))

    trocar_senha = cursor.fetchone()

    if not trocar_senha:
        return jsonify({ 'message': 'Valide seu email para alterar a senha.' }), 400

    if trocar_senha[0] is not True:
        return jsonify({ 'message': 'Valide seu email para alterar a senha.' }), 400

    if not validar_senha(nova_senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, um número e um caractere especial."})

    nova_senha_hash = generate_password_hash(nova_senha).decode('utf-8')

    cursor.execute('''
        UPDATE CADASTRO
        SET SENHA = ?, TROCAR_SENHA = NULL
        WHERE EMAIL = ?
    ''', (nova_senha_hash, email))

    con.commit()
    cursor.close()

    return jsonify({ "message" : "Senha alterada com sucesso!" }), 200
#========================================================================================================================================
@app.route('/avaliacoes', methods=['GET'])
def get_avaliacoes():
    id_cadastrof = request.args.get('id_cadastrof')
    try:
        cur = con.cursor()
        if id_cadastrof:
            cur.execute("SELECT * FROM AVALIACAO WHERE ID_CADASTROF = ?", (id_cadastrof,))
        else:
            cur.execute("SELECT * FROM AVALIACAO")
        rows = cur.fetchall()
        cur.close()

        avaliacoes = []
        for row in rows:
            avaliacoes.append({
                'id_avaliacao': row[0],
                'id_cadastro': row[1],
                'id_cadastrof': row[2],
                'nota': row[3]
            })
        return jsonify(avaliacoes), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/deixar_avaliacoes', methods=['POST'])
def criar_avaliacao():
    data = request.json
    id_cadastro = data.get('id_cadastro')
    id_cadastrof = data.get('id_cadastrof')
    nota = data.get('nota')

    if not all([id_cadastro, id_cadastrof, nota]):
        return jsonify({'error': 'Dados incompletos'}), 400
    if not (1 <= nota <= 5):
        return jsonify({'error': 'Nota deve ser entre 1 e 5'}), 400

    try:
        cur = con.cursor()
        cur.execute("INSERT INTO AVALIACAO (ID_CADASTRO, ID_CADASTROF, NOTA) VALUES (?, ?, ?)",
                    (id_cadastro, id_cadastrof, nota))
        con.commit()
        cur.close()
        return jsonify({'message': 'Avaliação criada com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/avaliacoes/<int:id_avaliacao>', methods=['PUT'])
def atualizar_avaliacao(id_avaliacao):
    data = request.json
    nota = data.get('nota')

    if nota is None:
        return jsonify({'error': 'Nota é obrigatória'}), 400
    if not (1 <= nota <= 5):
        return jsonify({'error': 'Nota deve ser entre 1 e 5'}), 400

    try:
        cur = con.cursor()
        cur.execute("UPDATE AVALIACAO SET NOTA = ? WHERE ID_AVALIACAO = ?", (nota, id_avaliacao))
        if cur.rowcount == 0:
            return jsonify({'error': 'Avaliação não encontrada'}), 404
        con.commit()
        cur.close()
        return jsonify({'message': 'Avaliação atualizada com sucesso!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#========================================================================================================================================
@app.route('/usuario/relatorio', methods=['GET'])
def usuario_relatorio():
    cursor = con.cursor()
    cursor.execute("SELECT nome, cpf, data_nascimento, email, cidade, cargo FROM cadastro")
    usuarios = cursor.fetchall()
    cursor.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Cores
    vermelho = (200, 0, 0)
    preto = (0, 0, 0)
    cinza = (245, 245, 245)

    # Título
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*vermelho)
    pdf.cell(0, 10, "Relatório de Usuários", ln=True, align='C')
    pdf.set_draw_color(*vermelho)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    # Cabeçalho da tabela
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(*preto)
    pdf.set_fill_color(*vermelho)
    headers = ["Nome", "CPF", "Nascimento", "Email", "Cidade", "Cargo"]
    widths = [35, 30, 30, 50, 25, 25]
    for header, width in zip(headers, widths):
        pdf.cell(width, 10, header, 1, 0, 'C', 1)
    pdf.ln()

    # Linhas de dados
    pdf.set_font("Arial", '', 11)
    fill = False

    for user in usuarios:
        pdf.set_fill_color(*(cinza if fill else (255, 255, 255)))
        for item, width in zip(user, widths):
            pdf.cell(width, 10, str(item), 1, 0, 'C', 1)
        pdf.ln()
        fill = not fill

    # Linha final
    pdf.ln(5)
    pdf.set_line_width(0.5)
    pdf.set_draw_color(*vermelho)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # Total de usuários
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(*preto)
    pdf.cell(0, 10, f"Total de Usuários Cadastrados: {len(usuarios)}", ln=True, align='C')

    # Exporta o PDF
    pdf_path = "relatorio_usuario.pdf"
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')
@app.route('/promo/relatorio', methods=['GET'])
def promocao_relatorio():
    cursor = con.cursor()
    cursor.execute("SELECT id_promo, titulopromo, duracaopromo, generopromo, descricaopromo FROM promocao")
    promocoes = cursor.fetchall()
    cursor.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    vermelho = (200, 0, 0)
    preto = (0, 0, 0)
    cinza = (245, 245, 245)

    # Título
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*vermelho)
    pdf.cell(0, 10, "Relatório de Promoções", ln=True, align='C')
    pdf.set_draw_color(*vermelho)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    # Cabeçalho
    headers = ["ID", "Título", "Duração", "Gênero", "Descrição"]
    widths = [15, 50, 25, 30, 70]
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(*preto)
    pdf.set_fill_color(*vermelho)
    for header, width in zip(headers, widths):
        pdf.cell(width, 10, header, 1, 0, 'C', 1)
    pdf.ln()

    # Dados
    pdf.set_font("Arial", '', 11)
    fill = False
    for promo in promocoes:
        pdf.set_fill_color(*(cinza if fill else (255, 255, 255)))
        for item, width in zip(promo, widths):
            texto = str(item)[:width // 2 + 10]  # Limita o texto
            pdf.cell(width, 10, texto, 1, 0, 'C', 1)
        pdf.ln()
        fill = not fill

    # Total
    pdf.ln(5)
    pdf.set_draw_color(*vermelho)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(*preto)
    pdf.cell(0, 10, f"Total de Promoções Cadastradas: {len(promocoes)}", ln=True, align='C')

    pdf_path = "relatorio_promocao.pdf"
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')
@app.route('/top_filmes_pdf', methods=['GET'])
def top_filmes_pdf():
    try:
        query = """
            SELECT upper(COALESCE(cf.TITULO, '')), cf.ID_CADASTROF, r.VALOR_TOTAL
            FROM RESERVA r
            LEFT JOIN SESSAO s ON s.ID_SESSAO = r.ID_SESSAO
            LEFT JOIN CADASTRO_FILME cf ON cf.ID_CADASTROF = s.ID_CADASTROF
        """

        cursor = con.cursor()
        cursor.execute(query)
        filmes = cursor.fetchall()
        cursor.close()

        # Soma por título
        filmes_soma = {}
        for filme in filmes:
            titulo = filme[0]
            valor_total = filme[2] or 0
            filmes_soma[titulo] = filmes_soma.get(titulo, 0) + valor_total

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        vermelho = (200, 0, 0)
        preto = (0, 0, 0)
        cinza = (245, 245, 245)

        # Título
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(*vermelho)
        pdf.cell(0, 10, "Relatório de Bilheteria dos Filmes", ln=True, align='C')
        pdf.set_draw_color(*vermelho)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        # Cabeçalho
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(*preto)
        pdf.set_fill_color(*vermelho)
        pdf.cell(140, 10, "Título", 1, 0, 'C', 1)
        pdf.cell(50, 10, "Bilheteria (R$)", 1, 1, 'C', 1)

        # Dados
        pdf.set_font("Arial", '', 11)
        fill = False
        for titulo, bilheteria in sorted(filmes_soma.items(), key=lambda x: x[1], reverse=True):
            pdf.set_fill_color(*(cinza if fill else (255, 255, 255)))
            pdf.cell(140, 10, titulo[:50], 1, 0, 'C', 1)
            pdf.cell(50, 10, f"{bilheteria:.2f}", 1, 1, 'C', 1)
            fill = not fill

        pdf_path = "relatorio_top_filmes.pdf"
        pdf.output(pdf_path)
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        print(f"Erro: {e}")
        return jsonify({"erro": "Ocorreu um erro ao gerar o PDF dos filmes"}), 500
@app.route('/total_ingressos_filmes_pdf', methods=['GET'])
def total_ingressos_filmes_pdf():
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM reserva WHERE LOWER(STATUS) = 'reservado'")
        resultado = cur.fetchone()
        cur.close()

        total_ingressos = resultado[0] if resultado else 0

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        vermelho = (200, 0, 0)
        preto = (0, 0, 0)

        # Título
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(*vermelho)
        pdf.cell(0, 10, "Total de Ingressos Vendidos", ln=True, align='C')
        pdf.set_draw_color(*vermelho)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(10)

        # Texto
        pdf.set_font("Arial", '', 12)
        pdf.set_text_color(*preto)
        pdf.cell(0, 10, f"Total de ingressos reservados: {total_ingressos}", ln=True, align='C')

        pdf_path = "relatorio_total_ingressos.pdf"
        pdf.output(pdf_path)
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        return jsonify({"erro": "Erro ao gerar PDF do total de ingressos"}), 500
@app.route('/admin/vendas_por_sessao_pdf', methods=['GET'])
def vendas_por_sessao_pdf():
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT 
                s.ID_SESSAO,
                f.TITULO,
                COUNT(ra.ID_ASSENTO) AS total_vendas
            FROM 
                sessao s
            LEFT JOIN 
                reserva r ON s.ID_SESSAO = r.ID_SESSAO
            LEFT JOIN 
                reserva_assentos ra ON r.ID_RESERVA = ra.ID_RESERVA
            LEFT JOIN 
                cadastro_filme f ON s.ID_CADASTROF = f.ID_CADASTROF
            GROUP BY 
                s.ID_SESSAO, f.TITULO
            ORDER BY 
                f.TITULO
        """)
        resultados = cur.fetchall()
        cur.close()

        if not resultados:
            return jsonify({'mensagem': 'Nenhuma sessão encontrada'}), 404

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        vermelho = (200, 0, 0)
        preto = (0, 0, 0)

        # Cabeçalho
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(*vermelho)
        pdf.cell(0, 10, "Relatório de Vendas por Sessão", ln=True, align='C')
        pdf.set_draw_color(*vermelho)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(10)

        # Tabela
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(*preto)
        pdf.cell(40, 10, "ID Sessão", 1)
        pdf.cell(100, 10, "Título do Filme", 1)
        pdf.cell(40, 10, "Total de Vendas", 1)
        pdf.ln()

        pdf.set_font("Arial", '', 12)
        for linha in resultados:
            id_sessao, titulo, total = linha
            pdf.cell(40, 10, str(id_sessao), 1)
            pdf.cell(100, 10, str(titulo), 1)
            pdf.cell(40, 10, str(total), 1)
            pdf.ln()

        pdf_path = "relatorio_vendas_por_sessao.pdf"
        pdf.output(pdf_path)
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        return jsonify({'erro': f'Erro ao gerar PDF: {str(e)}'}), 500
@app.route('/avaliacoes_pdf', methods=['GET'])
def avaliacoes_pdf():
    id_cadastrof = request.args.get('id_cadastrof')
    try:
        cur = con.cursor()
        if id_cadastrof:
            cur.execute("SELECT * FROM AVALIACAO WHERE ID_CADASTROF = ?", (id_cadastrof,))
        else:
            cur.execute("SELECT * FROM AVALIACAO")
        rows = cur.fetchall()
        cur.close()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        vermelho = (200, 0, 0)
        preto = (0, 0, 0)
        cinza = (245, 245, 245)

        # Título
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(*vermelho)
        titulo = "Relatório de Avaliações"
        if id_cadastrof:
            titulo += f" - Filme ID {id_cadastrof}"
        pdf.cell(0, 10, titulo, ln=True, align='C')
        pdf.set_draw_color(*vermelho)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(10)

        # Cabeçalho
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(*preto)
        pdf.set_fill_color(*vermelho)
        headers = ["ID Aval.", "ID Cadastro", "ID Filme", "Nota"]
        widths = [30, 40, 40, 30]
        for h, w in zip(headers, widths):
            pdf.cell(w, 10, h, 1, 0, 'C', 1)
        pdf.ln()

        # Dados
        pdf.set_font("Arial", '', 11)
        fill = False
        for row in rows:
            pdf.set_fill_color(*(cinza if fill else (255, 255, 255)))
            for item, w in zip(row[:4], widths):
                pdf.cell(w, 10, str(item), 1, 0, 'C', 1)
            pdf.ln()
            fill = not fill

        pdf_path = "relatorio_avaliacoes.pdf"
        pdf.output(pdf_path)
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/admin/historico_reservas_pdf', methods=['GET'])
def historico_reservas_pdf():
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT r.id_sessao, r.id_cadastro, r.valor_total,
                   s.id_sala, s.id_cadastrof, s.datasessao, s.valor_assento,
                   c.nome AS nome_usuario,
                   f.titulo AS titulo_filme,
                   sala.nome_sala
            FROM reserva r
            JOIN sessao s ON r.id_sessao = s.id_sessao
            JOIN cadastro c ON r.id_cadastro = c.id_cadastro
            JOIN cadastro_filme f ON s.id_cadastrof = f.id_cadastrof
            JOIN salas sala ON s.id_sala = sala.id_sala
            ORDER BY s.datasessao
        """)
        reservas = cur.fetchall()
        cur.close()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", style='B', size=16)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(200, 10, "Histórico de Reservas", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", style='B', size=11)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(40, 10, "Usuário", 1, 0, 'C', 1)
        pdf.cell(40, 10, "Filme", 1, 0, 'C', 1)
        pdf.cell(30, 10, "Sala", 1, 0, 'C', 1)
        pdf.cell(40, 10, "Data Sessão", 1, 0, 'C', 1)
        pdf.cell(20, 10, "R$ Ass.", 1, 0, 'C', 1)
        pdf.cell(20, 10, "R$ Total", 1, 1, 'C', 1)

        pdf.set_font("Arial", size=10)
        for r in reservas:
            data_formatada = r[5].strftime('%d/%m/%Y %H:%M')
            pdf.cell(40, 10, str(r[7])[:20], 1, 0, 'C')
            pdf.cell(40, 10, str(r[8])[:20], 1, 0, 'C')
            pdf.cell(30, 10, str(r[9])[:15], 1, 0, 'C')
            pdf.cell(40, 10, data_formatada, 1, 0, 'C')
            pdf.cell(20, 10, f"{float(r[6]):.2f}", 1, 0, 'C')
            pdf.cell(20, 10, f"{float(r[2]):.2f}", 1, 1, 'C')

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        pdf_path = f"static/pdfs/historico_reservas_{timestamp}.pdf"
        pdf.output(pdf_path)

        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
@app.route('/historico_reservas_pdf/<int:id_cadastro>', methods=['GET'])
def historico_reservas_individual_pdf(id_cadastro):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_logado = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    if id_usuario_logado != id_cadastro and not verifica_adm(id_usuario_logado):
        return jsonify({'mensagem': 'Acesso negado'}), 403

    try:
        cur = con.cursor()
        cur.execute("""
            SELECT r.id_sessao, r.id_cadastro, r.valor_total,
                   s.id_sala, s.id_cadastrof, s.datasessao, s.valor_assento,
                   c.nome AS nome_usuario,
                   f.titulo AS titulo_filme,
                   sala.nome_sala
            FROM reserva r
            JOIN sessao s ON r.id_sessao = s.id_sessao
            JOIN cadastro c ON r.id_cadastro = c.id_cadastro
            JOIN cadastro_filme f ON s.id_cadastrof = f.id_cadastrof
            JOIN salas sala ON s.id_sala = sala.id_sala
            WHERE r.id_cadastro = ?
            ORDER BY s.datasessao
        """, (id_cadastro,))
        reservas = cur.fetchall()
        cur.close()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=16)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 10, f"Histórico de Reservas - Usuário {id_cadastro}", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", style='B', size=12)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(40, 10, "Data Sessão", 1, 0, 'C', 1)
        pdf.cell(50, 10, "Título Filme", 1, 0, 'C', 1)
        pdf.cell(40, 10, "Nome Sala", 1, 0, 'C', 1)
        pdf.cell(30, 10, "Valor Assento", 1, 0, 'C', 1)
        pdf.cell(30, 10, "Valor Total", 1, 1, 'C', 1)

        pdf.set_font("Arial", size=11)
        for reserva in reservas:
            data_sessao = reserva[5].strftime('%d/%m/%Y %H:%M')
            pdf.cell(40, 10, data_sessao, 1, 0, 'C')
            pdf.cell(50, 10, reserva[8][:25], 1, 0, 'C')
            pdf.cell(40, 10, reserva[9][:20], 1, 0, 'C')
            pdf.cell(30, 10, f"R$ {float(reserva[6]):.2f}", 1, 0, 'C')
            pdf.cell(30, 10, f"R$ {float(reserva[2]):.2f}", 1, 1, 'C')

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        pdf_path = f"static/pdfs/historico_reservas_usuario_{id_cadastro}_{timestamp}.pdf"
        pdf.output(pdf_path)

        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
#========================================================================================================================================
@app.route('/cinema/<int:id_cine>', methods=['GET'])
def mostrar_cinema(id_cine):
    cursor = con.cursor()

    cursor.execute("""
        SELECT ID_CINE, CHAVE_PIX, NOME, CIDADE
        FROM CONFIG_CINE
        WHERE ID_CINE = ?
    """, (id_cine,))

    cinema = cursor.fetchone()  # Pega o primeiro resultado, pois id_cine é único

    cursor.close()

    if cinema:
        # Se o cinema for encontrado, retorna os dados em formato JSON
        return jsonify({
            "id_cine": cinema[0],
            "chave_pix": cinema[1],
            "nome": cinema[2],
            "cidade": cinema[3]
        })
    else:
        # Caso o cinema não seja encontrado
        return jsonify({"error": "Cinema não encontrado"}), 404
@app.route('/editar-cinema/<int:id_cine>', methods=['PUT'])
def editar_cinema(id_cine):
    data = request.json
    chave_pix = data.get('chave_pix')
    nome = data.get('nome')
    cidade = data.get('cidade')

    if not chave_pix or not nome or not cidade:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    cursor = con.cursor()
    cursor.execute("""
        UPDATE CONFIG_CINE
        SET CHAVE_PIX = ?, NOME = ?, CIDADE = ?
        WHERE ID_CINE = ?
    """, (chave_pix, nome, cidade, id_cine))

    con.commit()
    cursor.close()

    return jsonify({"message": "Dados do cinema atualizados com sucesso!"})
@app.route('/editar-logo', methods=['POST'])
def editar_logo():
    if 'logo' not in request.files:
        return jsonify({"error": "Arquivo logo não enviado"}), 400

    logo = request.files['logo']

    if logo.filename == '':
        return jsonify({"error": "Nome do arquivo inválido"}), 400

    # Salvar a logo na pasta desejada
    pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "logo_cinema")
    os.makedirs(pasta_destino, exist_ok=True)

    nome_arquivo = "logo_cinema.png"  # Pode usar extensão conforme a do arquivo recebido
    caminho_logo = os.path.join(pasta_destino, nome_arquivo)

    logo.save(caminho_logo)

    return jsonify({"message": "Logo atualizada com sucesso!", "path": caminho_logo})