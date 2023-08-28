#Importaciones para utilizar framework Flask
from flask import Flask, request, jsonify
import re #Validar contraseñas
import mysql.connector #Conectar y trabajar con base de datos mysql
from hashlib import sha256

app = Flask(__name__)

# Crear y conectar a la base de datos MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="linux",
    database="app"
)
cursor = conn.cursor() #Crea un cursor, se utiliza para ejecutar consultas

# Función para validar la contraseña según los requisitos
def validate_password(password):
    if (len(password) < 8 or len(password) > 15 or #La contraseña debe tener una longitud mínima de 8 caracteres y una longitud máxima de 15 caracteres.
            not re.search("[a-z]", password) or #La contraseña debe contener al menos una letra minúscula (caracteres de la a a la z).
            not re.search("[A-Z]", password) or #La contraseña debe contener al menos una letra mayúscula (caracteres de la A a la Z).
            not re.search("[!\"#$%&/()]", password)):#La contraseña debe contener al menos un carácter especial entre los siguientes: !, ", #, $, %, &, /, (, ).
        return False
    return True

# Función para encriptar una contraseña
def encrypt_password(password):
    return sha256(password.encode()).hexdigest()

#Define un endpoint con soilicitudes POST
@app.route('/registro', methods=['POST'])
def registro_usuario(): #
    data = request.json
    
    required_fields = ['correo', 'password', 'nombreusuario', 'fecha_vencimiento']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Datos incompletos'}), 400
    
    correo = data['correo']
    password = data['password']
    nombreusuario = data['nombreusuario']
    fecha_vencimiento = data['fecha_vencimiento']
    
    if not validate_password(password):
        return jsonify({'error': 'Contraseña no cumple con los requisitos'}), 400
    
    hashed_password = encrypt_password(password)
    
    # Insertar el nuevo usuario en la base de datos MySQL
    query = "INSERT INTO usuario (nombreusuario, correo, password, fecha_vencimiento) VALUES (%s, %s, %s, %s)"
    values = (nombreusuario, correo, hashed_password, fecha_vencimiento)
    cursor.execute(query, values)
    conn.commit()
    
    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

#Define un endpoint con soilicitudes GET
@app.route('/usuarios', methods=['GET'])
def get_usuarios():
    cursor.execute("SELECT idusuario, nombreusuario, correo, fecha_vencimiento FROM usuario") #ejecuta una consulta SQL en la base de datos.
    usuarios = cursor.fetchall()#Después de ejecutar la consulta, se utiliza fetchall() para obtener todos los resultados de la consulta. Esto devuelve una lista de tuplas, donde cada tupla contiene los valores de las columnas seleccionadas.
    response = [{"idusuario": user[0], "nombreusuario": user[1], "correo": user[2], "fecha_vencimiento": str(user[3])} for user in usuarios]#Aquí se crea una lista de diccionarios llamada response, que se construye utilizando una comprensión de lista
    return jsonify(response) #La función jsonify() toma la lista de diccionarios response y la convierte en una respuesta JSON válida que se puede enviar como resultado de la solicitud.

#Define un endpoitn con solicitudes POST
@app.route('/login', methods=['POST'])
def login():
    data = request.json #Obtiene datos enviados en la solicitud POST en formato JSON
    #verifica si todos los datos requeridos ('nombreusuario' y 'password') están presentes en los datos. Si no lo están, se devuelve un mensaje de error JSON junto con el código de estado HTTP 400 (Bad Request), indicando que los datos son insuficientes.
    if not data or 'nombreusuario' not in data or 'password' not in data:#
        return jsonify({'error': 'Datos incompletos'}), 400
    #Se obtienen el valor de nombreusuario y password
    nombreusuario = data['nombreusuario']
    password = data['password']

    #Se utiliza la función encrypt_password() para encriptar la contraseña proporcionada en la solicitud. Esto asegura que se compare con la contraseña almacenada en la base de datos en su forma encriptada.
    hashed_password = encrypt_password(password)

    #Se ejecuta una consulta SQL para obtener la contraseña almacenada en la base de datos correspondiente al nombre de usuario proporcionado. 
    cursor.execute("SELECT password FROM usuario WHERE nombreusuario = %s", (nombreusuario,))
    #obtiene la primera fila de resultados de la consulta. En este caso, como estamos seleccionando solo una columna (password), obtenemos la contraseña almacenada.
    stored_password = cursor.fetchone()
    
    #compara la contraseña encriptada proporcionada con la contraseña almacenada en la base de datos.
    if stored_password and hashed_password == stored_password[0]:
        return jsonify({'message': 'Inicio de sesión exitoso'}), 200
    else:
        return jsonify({'error': 'Credenciales incorrectas'}), 401

#Define un endpoint con solicitudes DELETE
@app.route('/eliminar_usuario', methods=['DELETE'])
def eliminar_usuario():
    data = request.json #Obtiene datos enviados en la solicitud POST en formato JSON
    if not data or 'nombreusuario' not in data: #Verifica si los datos requeridos están presentes en los datos
        return jsonify({'error': 'Datos incompletos'}), 400
    
    nombreusuario = data['nombreusuario']
    #Se construye una consulta SQL para eliminar el usuario de la base de datos basado en el nombre de usuario proporcionado.
    query = "DELETE FROM usuario WHERE nombreusuario = %s"
    cursor.execute(query, (nombreusuario,)) #Ejecuta la consulta SQL con el valor del nombre de usuario como parámetro.
    #Confirma los cambios en la base de datos, efectuando la eliminación del usuario.
    conn.commit()
    #Si la eliminación es exitosa, se devuelve un mensaje de éxito JSON junto con el código de estado HTTP 200 (OK), indicando que el usuario ha sido eliminado exitosamente.
    return jsonify({'message': f'Usuario {nombreusuario} eliminado exitosamente'}), 200


#Esta línea indica que esta función manejará solicitudes PUT en la ruta /actualizar_usuario.
@app.route('/actualizar_usuario', methods=['PUT'])
def actualizar_usuario():
    data = request.json #Obtiene los datos enviados en la solicitud PUT en formato JSON.
    #verifica si los datos requeridos ('nombreusuario') están presentes en los datos. Si no lo están, se devuelve un mensaje de error JSON junto con el código de estado HTTP 400 (Bad Request), indicando que los datos son insuficientes.
    if not data or 'nombreusuario' not in data:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    #Se obtiene el valor de 'nombreusuario' de los datos de la solicitud y se crea un diccionario vacío llamado nuevos_datos. Este diccionario se utilizará para almacenar las actualizaciones que se realizarán en la base de datos.
    nombreusuario = data['nombreusuario']
    nuevos_datos = {}
    
    #n esta sección, se verifica si existen claves como 'correo', 'password' y 'fecha_vencimiento' en los datos de la solicitud.
    if 'correo' in data:
        nuevos_datos['correo'] = data['correo']
    if 'password' in data:
        if not validate_password(data['password']):
            return jsonify({'error': 'Contraseña no cumple con los requisitos'}), 400
        nuevos_datos['password'] = encrypt_password(data['password'])
    if 'fecha_vencimiento' in data:
        nuevos_datos['fecha_vencimiento'] = data['fecha_vencimiento']
    
    if not nuevos_datos:
        return jsonify({'error': 'No se proporcionaron datos para actualizar'}), 400
    
    #Se construye una consulta SQL para actualizar los campos del usuario en la base de datos.
    #contiene una cadena que especifica los campos a actualizar y sus valores usando JOIN y %s para los valores.
    update_fields = ", ".join([f"{field} = %s" for field in nuevos_datos.keys()])
    query = f"UPDATE usuario SET {update_fields} WHERE nombreusuario = %s"
    update_values = tuple(nuevos_datos.values()) + (nombreusuario,)
    cursor.execute(query, update_values)
    conn.commit()
    #Si la actualización es exitosa, se devuelve un mensaje de éxito JSON junto con el código de estado HTTP 200, indicando que los datos del usuario han sido actualizados con éxito.
    return jsonify({'message': f'Datos de usuario {nombreusuario} actualizados exitosamente'}), 200

@app.route('/proveedores', methods=['GET'])
def obtener_proveedores():
    query = "SELECT * FROM proveedores"
    cursor.execute(query)
    proveedores = cursor.fetchall()
    result = []
    for proveedor in proveedores:
        result.append({
            'idproveedor': proveedor[0],
            'nombre_empresa': proveedor[1],
            'contacto': proveedor[2],
            'direccion_empresa': proveedor[3],
            'telefono_empresa': proveedor[4],
            'correo_empresa': proveedor[5],
            'fecha_asociacion': proveedor[6],
            'idusuario': proveedor[7]
        })
    return jsonify(result), 200

@app.route('/proveedores', methods=['POST'])
def agregar_proveedor():
    data = request.json
    required_fields = ['nombre_empresa', 'contacto', 'direccion_empresa', 'telefono_empresa', 'correo_empresa', 'fecha_asociacion', 'idusuario']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Datos incompletos'}), 400

    query = "INSERT INTO proveedores (nombre_empresa, contacto, direccion_empresa, telefono_empresa, correo_empresa, fecha_asociacion, idusuario) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    values = (data['nombre_empresa'], data['contacto'], data['direccion_empresa'], data['telefono_empresa'], data['correo_empresa'], data['fecha_asociacion'], data['idusuario'])
    cursor.execute(query, values)
    conn.commit()

    return jsonify({'message': 'Proveedor agregado exitosamente'}), 201

@app.route('/medicamentos', methods=['GET'])
def obtener_medicamentos():
    query = "SELECT * FROM medicamentos"
    cursor.execute(query)
    medicamentos = cursor.fetchall()
    result = []
    for medicamento in medicamentos:
        result.append({
            'idmedicamento': medicamento[0],
            'nombre_medicamento': medicamento[1],
            'precio': str(medicamento[2]), # Convertir el precio (DECIMAL) a string para evitar problemas de serialización
            'fecha_caducidad': medicamento[3],
            'composicion': medicamento[4],
            'indicaciones': medicamento[5],
            'contraindicaciones': medicamento[6],
            'idproveedor': medicamento[7]
        })
    return jsonify(result), 200

@app.route('/medicamentos', methods=['POST'])
def agregar_medicamento():
    data = request.json
    required_fields = ['nombre_medicamento', 'precio', 'fecha_caducidad', 'composicion', 'indicaciones', 'contraindicaciones', 'idproveedor']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Datos incompletos'}), 400

    query = "INSERT INTO medicamentos (nombre_medicamento, precio, fecha_caducidad, composicion, indicaciones, contraindicaciones, idproveedor) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    values = (data['nombre_medicamento'], data['precio'], data['fecha_caducidad'], data['composicion'], data['indicaciones'], data['contraindicaciones'], data['idproveedor'])
    cursor.execute(query, values)
    conn.commit()

    return jsonify({'message': 'Medicamento agregado exitosamente'}), 201


if __name__ == '__main__':
    app.run(debug=True)
    conn.close()