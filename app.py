from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response # Importado make_response
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import zipfile
import os
from datetime import datetime # Solo una importación de datetime
import json
import re
from elasticsearch import Elasticsearch, exceptions as es_exceptions # Agregado es_exceptions
from bson.objectid import ObjectId # Solo una importación de ObjectId


app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqu'  # Cambia esto por una clave secreta segura y consistente

# Agregar la función now al contexto de la plantilla
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Versión de la aplicación
VERSION_APP = "Versión 2.2 del Mayo 22 del 2025"
CREATOR_APP = "Nombre del creador/ruta github"
mongo_uri   = os.environ.get("MONGO_URI")

if not mongo_uri:
    uri         = "mongodb+srv://mbolivarc1:mbolivarc1@cluster0.jrpytuu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    mongo_uri   = uri

# Función para conectar a MongoDB
def connect_mongo():
    try:
        client_mongo_conn = MongoClient(mongo_uri, server_api=ServerApi('1'))
        client_mongo_conn.admin.command('ping')
        return client_mongo_conn
    except Exception as e:
        print(f"Error al conectar a MongoDB: {e}")
        return None

# Configuración de Elasticsearch
client = Elasticsearch(
    "https://336999300f6e4af1b074ef70213acc98.us-central1.gcp.cloud.es.io:443",
    api_key="d240aVFaY0J5bFJyYTVUSFd6ZW06MXdoS1dDMmxoNTFoRm9yaU1nNFdlQQ=="
)
INDEX_NAME = "ucentral_test" # Mantenemos ucentral_test según solicitado

# Función para obtener la configuración del índice Elasticsearch
def get_elasticsearch_config():
    index_settings = {
        "analysis": {
            "analyzer": {
                "my_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "my_stemmer", "ngram_filter"]
                }
            },
            "filter": {
                "my_stemmer": {
                    "type": "stemmer",
                    "name": "spanish"
                },
                "ngram_filter": {
                    "type": "edge_ngram",
                    "min_gram": 1,
                    "max_gram": 15,
                    "token_chars": ["letter"]
                }
            }
        }
    }
    index_mappings = {
        "properties": {
            "id": {"type": "wildcard"},  # Campo 'id' dentro del documento
            "categoria": {"type": "wildcard"},
            "clasificacion": {"type": "wildcard"},
            "subclasificacion": {"type": "wildcard"},
            "titulo": {"type": "wildcard"},
            "autor": {"type": "wildcard"},
            "fecha": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"}, # Formato de fecha especificado
            "texto": {"type": "text", "analyzer": "my_analyzer"}
        }
    }
    return index_settings, index_mappings

# Función para asegurar que el índice Elasticsearch exista con la configuración correcta
def ensure_elasticsearch_index(es_client, es_index_name):
    try:
        if not es_client.ping():
            print(f"ERROR: No se pudo conectar a Elasticsearch al intentar configurar el índice '{es_index_name}'.")
            return

        if not es_client.indices.exists(index=es_index_name):
            print(f"El índice '{es_index_name}' no fue encontrado. Creándolo ahora...")
            settings, mappings = get_elasticsearch_config()
            es_client.indices.create(index=es_index_name, settings=settings, mappings=mappings)
            print(f"Índice '{es_index_name}' creado exitosamente con la configuración y mapeos personalizados.")
        else:
            print(f"El índice '{es_index_name}' ya existe. No se realizarán cambios en la configuración existente.")
            # Opcional: Podrías querer actualizar los mapeos aquí si es seguro hacerlo.
            # ej: client.indices.put_mapping(index=es_index_name, properties=mappings["properties"])
            # Ten cuidado al actualizar mapeos en índices con datos.

    except es_exceptions.ConnectionError:
        print(f"ERROR: Falló la conexión a Elasticsearch durante la configuración del índice '{es_index_name}'. Verifica la conexión y las credenciales.")
    except Exception as e:
        print(f"ERROR: Ocurrió un error inesperado durante la configuración del índice Elasticsearch '{es_index_name}': {e}")

# Asegurar que el índice exista con la configuración correcta al iniciar la aplicación
if client: # Solo intentar si el cliente fue inicializado
    ensure_elasticsearch_index(client, INDEX_NAME)


# Decorador para añadir cabeceras anti-caché a las respuestas HTML
@app.after_request
def add_no_cache_headers(response):
    # print(f"DEBUG @app.after_request: Path: {request.path}, Response Mimetype: {response.mimetype}, Status: {response.status_code}")
    if response.mimetype == 'text/html':
        # print(f"DEBUG @app.after_request: Applying no-cache headers to HTML response for path: {request.path}")
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'  # HTTP 1.0.
        response.headers['Expires'] = '0'  # Proxies.
    # print(f"DEBUG @app.after_request: Final headers for {request.path}: {response.headers}")
    return response

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html', version=VERSION_APP,creador=CREATOR_APP)

@app.route('/contacto', methods=['GET', 'POST'])
def contacto():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        asunto = request.form.get('asunto')
        mensaje = request.form.get('mensaje')

        mensaje_doc = {
            "nombre": nombre,
            "email": email,
            "asunto": asunto,
            "mensaje": mensaje,
            "fecha": datetime.now()
        }

        client_mongo = None
        try:
            client_mongo = connect_mongo()
            if not client_mongo:
                return render_template('contacto.html',
                                   error_message="⚠️ Error: No se pudo conectar a la base de datos.",
                                   creador=CREATOR_APP,
                                   version=VERSION_APP)
            
            db = client_mongo['administracion']
            mensajes_collection = db['contacto_mensajes']
            mensajes_collection.insert_one(mensaje_doc)

            return render_template('contacto.html',
                                   success="✅ Tu mensaje fue enviado y almacenado correctamente.",
                                   creador=CREATOR_APP,
                                   version=VERSION_APP)
        except Exception as e:
            return render_template('contacto.html',
                                   error_message=f"⚠️ Error al guardar el mensaje: {str(e)}",
                                   creador=CREATOR_APP,
                                   version=VERSION_APP)
        finally:
            if client_mongo:
                client_mongo.close()

    return render_template('contacto.html',
                           creador=CREATOR_APP,
                           version=VERSION_APP)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_mongo = None
        try:
            client_mongo = connect_mongo()
            if not client_mongo:
                return render_template('login.html', error_message='Error de conexión con la base de datos. Por favor, intente más tarde.', version=VERSION_APP,creador=CREATOR_APP)
            
            db = client_mongo['administracion']
            security_collection = db['seguridad']
            usuario_form = request.form['usuario']
            password_form = request.form['password']
            
            user = security_collection.find_one({
                'usuario': usuario_form,
                'password': password_form
            })
            
            if user:
                session['usuario'] = usuario_form
                session.modified = True
                print(f"DEBUG /login [POST]: Usuario '{usuario_form}' ha iniciado sesión. Session: {list(session.items())}. Redirigiendo a gestion_proyecto.")
                
                response = make_response(redirect(url_for('gestion_proyecto')))
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
                return response
            else:
                print(f"DEBUG /login [POST]: Usuario o contraseña incorrectos para '{usuario_form}'.")
                return render_template('login.html', error_message='Usuario o contraseña incorrectos', version=VERSION_APP,creador=CREATOR_APP)
        except Exception as e:
            print(f"DEBUG /login [POST]: Error al validar credenciales: {str(e)}")
            return render_template('login.html', error_message=f'Error al validar credenciales: {str(e)}', version=VERSION_APP,creador=CREATOR_APP)
        finally:
            if client_mongo: 
                client_mongo.close()
    
    print(f"DEBUG /login [GET]: Accediendo. Session ANTES del check: {list(session.items())}")
    if 'usuario' in session:
        print(f"DEBUG /login [GET]: 'usuario' ({session.get('usuario')}) ENCONTRADO en sesión. Redirigiendo a gestion_proyecto. ¡ESTO PUEDE SER UN PROBLEMA SI OCURRE DESPUÉS DEL LOGOUT!")
        return redirect(url_for('gestion_proyecto'))
    
    print(f"DEBUG /login [GET]: 'usuario' NO encontrado en sesión. Mostrando formulario de login.")
    return render_template('login.html', version=VERSION_APP,creador=CREATOR_APP)

@app.route('/listar-usuarios')
def listar_usuarios():
    client_mongo = None 
    try:
        client_mongo = connect_mongo() 
        if not client_mongo:
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500
        
        db = client_mongo['administracion']
        security_collection = db['seguridad']
        usuarios = list(security_collection.find({}, {'password': 0}))
        for usuario_item in usuarios: 
            usuario_item['_id'] = str(usuario_item['_id'])
        
        return jsonify(usuarios)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if client_mongo: 
            client_mongo.close()

@app.route('/gestion_proyecto', methods=['GET', 'POST'])
def gestion_proyecto():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    try:
        client = connect_mongo()
        # Obtener lista de bases de datos
        databases = client.list_database_names()
        # Eliminar bases de datos del sistema
        system_dbs = ['admin', 'local', 'config']
        databases = [db for db in databases if db not in system_dbs]
        
        selected_db = request.form.get('database') if request.method == 'POST' else request.args.get('database')
        collections_data = []
        
        if selected_db:
            db = client[selected_db]
            collections = db.list_collection_names()
            for index, collection_name in enumerate(collections, 1):
                collection = db[collection_name]
                count = collection.count_documents({})
                collections_data.append({
                    'index': index,
                    'name': collection_name,
                    'count': count
                })
        
        return render_template('gestion/index.html',
                            databases=databases,
                            selected_db=selected_db,
                            collections_data=collections_data,
                            version=VERSION_APP,
                            creador=CREATOR_APP,
                            usuario=session['usuario'])
    except Exception as e:
        return render_template('gestion/index.html',
                            error_message=f'Error al conectar con MongoDB: {str(e)}',
                            version=VERSION_APP,
                            creador=CREATOR_APP,
                            usuario=session['usuario'])


@app.route('/crear-coleccion-form/<database>') 
def crear_coleccion_form(database):
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return render_template('gestion/crear_coleccion.html', 
                        database=database, 
                        usuario=session['usuario'],
                        version=VERSION_APP,
                        creador=CREATOR_APP)

@app.route('/crear-coleccion', methods=['POST'])
def crear_coleccion():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    database_form_val = request.form.get('database')
    collection_name_form = request.form.get('collection_name')
    zip_file_form = request.files.get('zip_file')
    error_msg = None
    success_msg = None
    documentos_insertados = 0
    client_mongo = None 

    try:
        if not all([database_form_val, collection_name_form, zip_file_form]):
            error_msg = 'Todos los campos son requeridos'
        else:
            client_mongo = connect_mongo() 
            if not client_mongo:
                error_msg = 'Error de conexión con MongoDB'
            else:
                db = client_mongo[database_form_val] 
                collection_obj = db[collection_name_form] 
                temp_dir = None 

                with zipfile.ZipFile(zip_file_form) as zip_ref: 
                    temp_dir = os.path.join(os.path.dirname(__file__), 'temp_zip_extract') 
                    os.makedirs(temp_dir, exist_ok=True)
                    zip_ref.extractall(temp_dir)
                    
                    for root, _, files in os.walk(temp_dir):
                        for file_item in files: 
                            if file_item.endswith('.json'):
                                file_path = os.path.join(root, file_item)
                                with open(file_path, 'r', encoding='utf-8-sig') as f:
                                    try:
                                        json_data = json.load(f)
                                        if isinstance(json_data, list):
                                            if json_data: 
                                                collection_obj.insert_many(json_data)
                                                documentos_insertados += len(json_data)
                                        else: 
                                            if json_data: 
                                                collection_obj.insert_one(json_data)
                                                documentos_insertados += 1
                                    except json.JSONDecodeError:
                                        print(f"Error al procesar el archivo JSON {file_item}")
                                    except Exception as e_insert:
                                        print(f"Error al insertar datos del archivo {file_item}: {str(e_insert)}")
                
                if documentos_insertados > 0:
                    success_msg = f'Se insertaron {documentos_insertados} documentos correctamente.'
                elif not error_msg: 
                    error_msg = 'No se insertaron documentos. Verifique el contenido de los archivos JSON.'

                if temp_dir and os.path.exists(temp_dir):
                    for root_d, dirs_d, files_d in os.walk(temp_dir, topdown=False):
                        for name_f in files_d:
                            os.remove(os.path.join(root_d, name_f))
                        for name_d in dirs_d:
                            os.rmdir(os.path.join(root_d, name_d))
                    os.rmdir(temp_dir)
        
    except Exception as e:
        error_msg = f'Error al crear la colección: {str(e)}'
    finally:
        if client_mongo: 
            client_mongo.close()

    return render_template('gestion/crear_coleccion.html',
                        success_message=success_msg,
                        error_message=error_msg,
                        database=database_form_val, 
                        usuario=session['usuario'],
                        version=VERSION_APP,
                        creador=CREATOR_APP)

@app.route('/ver-registros/<database>/<collection>')
def ver_registros(database, collection):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    client_mongo = None
    records_list = []
    error_msg = None
    try:
        client_mongo = connect_mongo()
        if not client_mongo:
            error_msg = 'Error de conexión con MongoDB'
        else:
            db = client_mongo[database]
            collection_obj = db[collection]  # ✅ Aquí está la corrección
            records_list = list(collection_obj.find().limit(100))
            for record_item in records_list:
                record_item['_id'] = str(record_item['_id'])

    except Exception as e:
        error_msg = f'Error al obtener registros: {str(e)}'
    finally:
        if client_mongo:
            client_mongo.close()

    return render_template('gestion/ver_registros.html',
                           database=database,
                           collection_name=collection,  # Este nombre se usa en el HTML
                           records=records_list,
                           error_message=error_msg,
                           version=VERSION_APP,
                           creador=CREATOR_APP,
                           usuario=session['usuario'])


@app.route('/obtener-registros', methods=['POST'])
def obtener_registros():
    if 'usuario' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    
    client_mongo = None 
    try:
        database_form = request.form.get('database')
        collection_form = request.form.get('collection')
        limit_form = int(request.form.get('limit', 100))
        
        client_mongo = connect_mongo() 
        if not client_mongo:
            return jsonify({'error': 'Error de conexión con MongoDB'}), 500
        
        db = client_mongo[database_form] 
        collection_obj = db[collection_form] 
        records = list(collection_obj.find().limit(limit_form))
        for record_item in records: 
            record_item['_id'] = str(record_item['_id'])
        
        return jsonify({'records': records})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if client_mongo: 
            client_mongo.close()

@app.route('/crear-base-datos-form')
def crear_base_datos_form():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return render_template('gestion/crear_base_datos.html',
                        version=VERSION_APP,
                        creador=CREATOR_APP,
                        usuario=session['usuario'])

@app.route('/crear-base-datos', methods=['POST'])
def crear_base_datos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    client_mongo = None 
    error_msg = None 
    database_name_form = request.form.get('database_name')
    collection_name_form = request.form.get('collection_name')

    try:
        valid_pattern = re.compile(r'^[a-zA-Z0-9_]+$')
        if not (database_name_form and collection_name_form and 
                valid_pattern.match(database_name_form) and 
                valid_pattern.match(collection_name_form)):
            error_msg = 'Los nombres de base de datos y colección son requeridos y no pueden contener tildes, espacios ni caracteres especiales.'
        else:
            client_mongo = connect_mongo() 
            if not client_mongo:
                error_msg = 'Error de conexión con MongoDB'
            else:
                db = client_mongo[database_name_form] 
                collection_obj = db[collection_name_form] 
                collection_obj.insert_one({'_init_': True}) 
                return redirect(url_for('gestion_proyecto', database=database_name_form))
        
        return render_template('gestion/crear_base_datos.html',
                            error_message=error_msg,
                            version=VERSION_APP,
                            creador=CREATOR_APP,
                            usuario=session['usuario'])
        
    except Exception as e:
        error_msg = f'Error al crear la base de datos: {str(e)}'
        return render_template('gestion/crear_base_datos.html',
                            error_message=error_msg,
                            version=VERSION_APP,
                            creador=CREATOR_APP,
                            usuario=session['usuario'])
    finally:
        if client_mongo: 
            client_mongo.close()


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/elasticAdmin')
def elasticAdmin():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    doc_count = 0
    error_msg = None
    try:
        if client.ping(): 
            # Re-asegurar que el índice esté configurado si por alguna razón no lo estuviera
            ensure_elasticsearch_index(client, INDEX_NAME)
            if client.indices.exists(index=INDEX_NAME):
                 doc_count = client.count(index=INDEX_NAME)['count']
            else:
                error_msg = f"El índice '{INDEX_NAME}' no existe. Intente crearlo o verifique la configuración."
        else:
            error_msg = "No se pudo conectar con Elasticsearch."
            
    except es_exceptions.ConnectionError:
        error_msg = "Error de conexión con Elasticsearch. Verifique que el servicio esté activo y accesible."
    except Exception as e:
        error_msg = f'Error al obtener información de Elasticsearch: {str(e)}'
        
    return render_template('gestion/ver_elasticAdmin.html',
                        index_name=INDEX_NAME,
                        doc_count=doc_count,
                        error_message=error_msg, 
                        version=VERSION_APP,
                        creador=CREATOR_APP,
                        usuario=session['usuario'])

@app.route('/elastic-agregar-documentos', methods=['GET', 'POST'])
def elastic_agregar_documentos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    error_msg = None
    success_msg = None

    if request.method == 'POST':
        temp_dir = None 
        try:
            if not client.ping():
                error_msg = "Error: No se pudo conectar con Elasticsearch. Verifique el servicio."
            # Asegurar que el índice tiene la configuración correcta antes de agregar documentos
            elif not client.indices.exists(index=INDEX_NAME):
                ensure_elasticsearch_index(client, INDEX_NAME) # Intenta crear/configurar
                if not client.indices.exists(index=INDEX_NAME): # Comprueba de nuevo
                     error_msg = f"Error: El índice '{INDEX_NAME}' no existe y no pudo ser creado. Verifique los logs."

            if error_msg: # Si hay error de conexión o índice, no continuar
                 pass # El error_msg ya está seteado
            elif 'zipFile' not in request.files or request.files['zipFile'].filename == '':
                error_msg = 'No se ha seleccionado ningún archivo'
            else:
                zip_file = request.files['zipFile']
                temp_dir = os.path.join(os.path.dirname(__file__), 'temp_elastic_upload')
                os.makedirs(temp_dir, exist_ok=True)
                zip_path = os.path.join(temp_dir, zip_file.filename)
                zip_file.save(zip_path)
                
                success_count = 0
                error_count = 0
                
                with zipfile.ZipFile(zip_path) as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                for root, _, files_list in os.walk(temp_dir): 
                    for file_item in files_list: 
                        if file_item.endswith('.json'):
                            file_path = os.path.join(root, file_item)
                            try:
                                with open(file_path, 'r', encoding='utf-8-sig') as f: # utf-8-sig para manejar BOM
                                    json_data = json.load(f)
                                    if isinstance(json_data, list):
                                        for doc_item in json_data:
                                            if doc_item: 
                                                # Usar el valor del campo 'id' del documento como _id de Elasticsearch
                                                # Si 'id' no está, Elasticsearch generará uno automáticamente
                                                es_doc_id = doc_item.get('id') 
                                                client.index(index=INDEX_NAME, document=doc_item, id=es_doc_id)
                                                success_count += 1
                                    else: 
                                        if json_data:
                                            es_doc_id = json_data.get('id')
                                            client.index(index=INDEX_NAME, document=json_data, id=es_doc_id)
                                            success_count += 1
                            except json.JSONDecodeError as json_err:
                                error_count += 1
                                print(f"Error de decodificación JSON en {file_item} para Elasticsearch: {str(json_err)}")
                            except Exception as e_index:
                                error_count += 1
                                print(f"Error procesando {file_item} para Elasticsearch: {str(e_index)}")
                
                if success_count > 0:
                    success_msg = f'Se indexaron {success_count} documentos exitosamente.'
                    if error_count > 0:
                         success_msg += f' Errores durante el proceso: {error_count}. Revise los logs del servidor.'
                
                if error_count > 0 and success_count == 0: 
                    error_msg = f'No se pudieron indexar documentos. Errores: {error_count}. Revise los logs.'
                    success_msg = None 
                elif success_count == 0 and error_count == 0 and not error_msg : # Evitar sobreescribir error_msg de conexión
                     error_msg = 'No se encontraron documentos JSON válidos para indexar en el ZIP.'

                # Limpieza del directorio temporal
                if temp_dir and os.path.exists(temp_dir):
                    for root_d, dirs_d, files_d in os.walk(temp_dir, topdown=False):
                        for name_f in files_d:
                            try:
                                os.remove(os.path.join(root_d, name_f))
                            except OSError as e_rm:
                                print(f"Error al eliminar archivo temporal {name_f}: {e_rm}")
                        for name_d in dirs_d:
                            try:
                                os.rmdir(os.path.join(root_d, name_d))
                            except OSError as e_rmdir:
                                 print(f"Error al eliminar directorio temporal {name_d}: {e_rmdir}")
                    try:
                        os.rmdir(temp_dir)
                    except OSError as e_rmroot:
                        print(f"Error al eliminar directorio temporal raíz {temp_dir}: {e_rmroot}")
            
        except es_exceptions.ConnectionError:
            error_msg = "Error de conexión con Elasticsearch al intentar agregar documentos."
            success_msg = None
        except Exception as e:
            error_msg = f'Error al procesar el archivo: {str(e)}'
            success_msg = None 
    
    return render_template('gestion/elastic_agregar_documentos.html',
                         index_name=INDEX_NAME,
                         success_message=success_msg,
                         error_message=error_msg, 
                         version=VERSION_APP,
                         creador=CREATOR_APP,
                         usuario=session['usuario'])

@app.route('/elastic-listar-documentos')
def elastic_listar_documentos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    documents = []
    error_msg = None
    try:
        if not client.ping():
            error_msg = "Error: No se pudo conectar con Elasticsearch."
        elif not client.indices.exists(index=INDEX_NAME):
            error_msg = f"Error: El índice '{INDEX_NAME}' no existe. Agregue documentos primero."
        else:
            response = client.search(
                index=INDEX_NAME,
                body={"query": {"match_all": {}}, "size": 100} # Aumentado a 100 para ver más
            )
            documents = response['hits']['hits']
            if not documents:
                error_msg = f"No se encontraron documentos en el índice '{INDEX_NAME}'."

    except es_exceptions.ConnectionError:
        error_msg = "Error de conexión con Elasticsearch."
    except es_exceptions.NotFoundError:
        error_msg = f"El índice '{INDEX_NAME}' no fue encontrado en Elasticsearch."
    except Exception as e:
        error_msg = f'Error al obtener documentos de Elasticsearch: {str(e)}'
        
    return render_template('gestion/elastic_listar_documentos.html',
                        index_name=INDEX_NAME,
                        documents=documents,
                        error_message=error_msg, 
                        version=VERSION_APP,
                        creador=CREATOR_APP,
                        usuario=session['usuario'])

@app.route('/elastic-eliminar-documento', methods=['POST'])
def elastic_eliminar_documento():
    if 'usuario' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    
    try:
        if not client.ping():
            return jsonify({'error': 'No se pudo conectar con Elasticsearch.'}), 500
            
        doc_id = request.form.get('doc_id')
        if not doc_id:
            return jsonify({'error': 'ID de documento no proporcionado'}), 400
        
        if not client.indices.exists(index=INDEX_NAME):
             return jsonify({'error': f"Índice '{INDEX_NAME}' no encontrado."}), 404

        response = client.delete(index=INDEX_NAME, id=doc_id)
        
        if response.get('result') == 'deleted': 
            return jsonify({'success': True, 'message': 'Documento eliminado correctamente.'})
        elif response.get('result') == 'not_found':
            return jsonify({'error': 'Documento no encontrado en Elasticsearch.', 'details': response.get('result')}), 404
        else:
            return jsonify({'error': 'Error al eliminar el documento desde Elasticsearch.', 'details': response.get('result', 'No details')}), 500
            
    except es_exceptions.ConnectionError:
        return jsonify({'error': 'Error de conexión con Elasticsearch.'}), 500
    except es_exceptions.NotFoundError: # Si el índice no existe o el doc_id no existe
        return jsonify({'error': 'Documento o índice no encontrado.'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/buscador', methods=['GET', 'POST'])
def buscador():
    hits = []
    aggregations = {}
    error_msg = None
    query_display_json = "" 
    
    search_type_form = request.form.get('search_type', '') if request.method == 'POST' else ''
    search_text_form = request.form.get('search_text', '') if request.method == 'POST' else ''
    # Asegurar que las fechas tengan un valor por defecto si están vacías
    fecha_desde_form = request.form.get('fecha_desde') if request.method == 'POST' else "1500-01-01"
    if not fecha_desde_form and request.method == 'POST': fecha_desde_form = "1500-01-01"

    fecha_hasta_form = request.form.get('fecha_hasta') if request.method == 'POST' else datetime.now().strftime("%Y-%m-%d")
    if not fecha_hasta_form and request.method == 'POST': fecha_hasta_form = datetime.now().strftime("%Y-%m-%d")


    if request.method == 'POST':
        try:
            if not client.ping():
                error_msg = "Error: No se pudo conectar con Elasticsearch para realizar la búsqueda."
            elif not client.indices.exists(index=INDEX_NAME):
                 error_msg = f"Error: El índice '{INDEX_NAME}' no existe. No se puede realizar la búsqueda."
            else:
                search_type = search_type_form
                search_text = search_text_form
                fecha_desde = fecha_desde_form
                fecha_hasta = fecha_hasta_form

                # Validar y asegurar valores por defecto para fechas si están vacías
                if not fecha_desde: fecha_desde = "1500-01-01"
                if not fecha_hasta: fecha_hasta = datetime.now().strftime("%Y-%m-%d")

                query_body = {
                    "query": {"bool": {"must": []}},
                    "aggs": {
                        "categoria": {"terms": {"field": "categoria.keyword", "size": 10, "order": {"_key": "asc"}}}, 
                        "clasificacion": {"terms": {"field": "clasificacion.keyword", "size": 10, "order": {"_key": "asc"}}}, 
                        "Fecha": {"date_histogram": {"field": "fecha", "calendar_interval": "year", "format": "yyyy"}}
                    },
                    "size": 100 
                }

                if search_text: 
                    if search_type == 'texto': # Búsqueda de frase en el campo 'texto'
                        query_body["query"]["bool"]["must"].append(
                            {"match_phrase": {"texto": {"query": search_text, "slop": 1}}}
                        )
                    elif search_type: # Búsqueda en un campo específico con wildcards implícitos si no presentes
                        query_body["query"]["bool"]["must"].append(
                            {"query_string": {"default_field": search_type, "query": search_text if "*" in search_text or "?" in search_text else f"*{search_text}*"}}
                        )
                    else: # Búsqueda general en múltiples campos (multi_match)
                        query_body["query"]["bool"]["must"].append({
                            "multi_match": {
                                "query": search_text,
                                "fields": ["texto", "titulo", "categoria", "clasificacion", "nombre", "autor", "id"] # Agregado 'id'
                            }
                        })
                
                # Siempre agregar el filtro de rango de fechas
                # El formato yyyy-MM-dd HH:mm:ss es para datos, yyyy-MM-dd para la query de rango está bien
                # Elasticsearch es flexible con los formatos de fecha en queries si el mapeo lo soporta.
                # Formato yyyy para años completos.
                range_query = {"range": {"fecha": {"format": "yyyy-MM-dd||yyyy-MM-dd HH:mm:ss||yyyy", "gte": fecha_desde, "lte": fecha_hasta}}}
                query_body["query"]["bool"]["must"].append(range_query)
                
                query_display_json = json.dumps(query_body, indent=2,ensure_ascii=False) # ensure_ascii para tildes
                
                response_es = client.search(index=INDEX_NAME, body=query_body)
                hits = response_es['hits']['hits']
                aggregations = response_es.get('aggregations', {})
                if not hits and not error_msg: # Si no hay error previo, pero no hay hits
                    error_msg = "No se encontraron resultados para su búsqueda."
        
        except es_exceptions.ConnectionError:
            error_msg = "Error de conexión con Elasticsearch durante la búsqueda."
        except es_exceptions.NotFoundError:
            error_msg = f"El índice de búsqueda '{INDEX_NAME}' no fue encontrado."
        except Exception as e:
            error_msg = f'Error en la búsqueda: {str(e)}'
            print(f"Error en buscador: {e}") 
    
    return render_template('buscador.html',
                        version=VERSION_APP,
                        creador=CREATOR_APP,
                        hits=hits,
                        aggregations=aggregations,
                        search_type=search_type_form, 
                        search_text=search_text_form,
                        fecha_desde=fecha_desde_form,
                        fecha_hasta=fecha_hasta_form,
                        error_message=error_msg,
                        query_display=query_display_json) 

@app.route('/api/search', methods=['POST'])
def search_api(): 
    if 'usuario' not in session: 
        return jsonify({'error': 'No autorizado'}), 401

    try:
        if not client.ping():
            return jsonify({'error': 'No se pudo conectar con Elasticsearch.'}), 503

        data = request.get_json()
        index_name_req = data.get('index', INDEX_NAME) # Usa el INDEX_NAME por defecto
        query_req = data.get('query')

        if not query_req:
            return jsonify({'error': 'Query no proporcionada'}), 400
        
        if not client.indices.exists(index=index_name_req):
            return jsonify({'error': f"Índice '{index_name_req}' no encontrado."}), 404

        response = client.search(index=index_name_req, body=query_req)
        return jsonify(response)

    except es_exceptions.ConnectionError:
        return jsonify({'error': 'Error de conexión con Elasticsearch.'}), 503
    except es_exceptions.NotFoundError:
        return jsonify({'error': f"Índice '{data.get('index', INDEX_NAME)}' no encontrado."}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ver-productos/<database>/<collection_name_route>/<registro_id>') 
def ver_productos(database, collection_name_route, registro_id):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    client_mongo = None 
    productos_data = []
    error_msg = None

    try:
        if not ObjectId.is_valid(registro_id): 
            error_msg = "ID de registro inválido."
        else:
            client_mongo = connect_mongo() 
            if not client_mongo:
                error_msg = "No se pudo conectar a MongoDB"
            else:
                db = client_mongo[database] 
                collection_obj = db[collection_name_route] 
                registro = collection_obj.find_one({"_id": ObjectId(registro_id)})

                if registro:
                    productos_data = registro.get('productos', [])
                    if not productos_data:
                         error_msg = "El registro no contiene 'productos' o la lista está vacía."
                else:
                    error_msg = "Registro no encontrado." 
            
    except Exception as e:
        error_msg = f"Error al obtener productos: {str(e)}"
    finally:
        if client_mongo: 
            client_mongo.close()

    return render_template(
        'gestion/ver_productos.html',
        productos=productos_data,
        database=database, 
        collection_name=collection_name_route, 
        registro_id=registro_id, 
        error_message=error_msg, 
        version=VERSION_APP,
        creador=CREATOR_APP,
        usuario=session.get('usuario') 
    )


@app.route('/ver-estadisticas/<database>/<collection_name_route>') 
def ver_estadisticas(database, collection_name_route):
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    client_mongo = None 
    stats_data = {}
    error_msg = None

    try:
        client_mongo = connect_mongo() 
        if not client_mongo:
            error_msg = "No se pudo conectar a MongoDB"
        else:
            db = client_mongo[database] 
            collection_obj = db[collection_name_route] 

            # Considerar paginación o muestreo para colecciones muy grandes
            # Limitar a los primeros 1000 documentos para el análisis de campos es una simplificación
            registros = list(collection_obj.find({}, limit=1000)) #_id siempre está
            
            if registros:
                # Obtener todos los campos únicos de los documentos muestreados
                all_fields = set()
                for r in registros:
                    all_fields.update(r.keys())
                if "_id" in all_fields:
                    all_fields.remove("_id") # Excluir _id del análisis general de campos

                for campo in sorted(list(all_fields)): # Ordenar para consistencia
                    valores = []
                    documentos_con_campo = 0
                    for r in registros:
                        if campo in r:
                            documentos_con_campo +=1
                            valor = r.get(campo)
                            if valor is not None: # Solo agregar valores no nulos para análisis de tipo y unicidad
                                valores.append(valor)
                    
                    if valores: # Si hay al menos un valor no nulo para este campo
                        # Intentar obtener el tipo del primer valor no nulo
                        tipo_dato = type(valores[0]).__name__
                        try:
                            # Para valores únicos, convertir a string para manejar tipos no hashables como listas o dicts
                            # Esto es una aproximación para la cuenta de unicidad.
                            valores_unicos_set = set(str(v) for v in valores) 
                        except TypeError: 
                            valores_unicos_set = set() # Si la conversión a str falla para algún elemento

                        stats_data[campo] = {
                            "tipo": tipo_dato, 
                            "total_documentos_con_campo": documentos_con_campo, 
                            "total_no_nulos": len(valores),
                            "valores_unicos_aprox": len(valores_unicos_set) # Renombrado para claridad
                        }
                    else: # El campo existe en algunos documentos, pero todos sus valores son None o está vacío
                         stats_data[campo] = {
                            "tipo": "N/A (todos nulos o ausentes en la muestra)",
                            "total_documentos_con_campo": documentos_con_campo,
                            "total_no_nulos": 0,
                            "valores_unicos_aprox": 0
                        }
            else:
                error_msg = "No hay registros en la colección para generar estadísticas."
        
    except Exception as e:
        error_msg = f"Error al generar estadísticas: {str(e)}"
        print(f"Error en ver_estadisticas: {e}") # Log del error
    finally:
        if client_mongo: 
            client_mongo.close()

    return render_template('gestion/ver_estadisticas.html',
                           stats=stats_data,
                           database=database,
                           collection_name=collection_name_route, 
                           error_message=error_msg, 
                           version=VERSION_APP,
                           creador=CREATOR_APP,
                           usuario=session['usuario'])


if __name__ == '__main__':
    # ensure_elasticsearch_index(client, INDEX_NAME) # Ya se llama después de inicializar el cliente globalmente
    app.run(debug=True)