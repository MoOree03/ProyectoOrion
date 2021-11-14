import re
from flask import Flask, render_template, request, flash, redirect, url_for, session,\
    g
import yagmail
from werkzeug.security import generate_password_hash, check_password_hash
import os
import utils
from db import get_db
import functools
from forms import NuevoProducto


correo_envia = 'mintic202221@gmail.com'
contraseña_envia = 'Mintic2022'
yag = yagmail.SMTP(user=correo_envia, password=contraseña_envia)


tema_recupera = '¿Olvidaste tu contraseña'


app = Flask(__name__)
app.secret_key = os.urandom(12)
inicioS = False
admin = False
superAdmin = False


@app.route('/', methods=['GET'])
def inicio():
    # Si inicio sesion -> Mostrar bienvenida, y cambio de navbar
    # Sino -> mantener rol de visitante
    return render_template('index.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)


@app.route('/iniciar', methods=['POST', 'GET'])
def iniciar():
    global inicioS
    global admin
    global superAdmin
    try:
        if request.method == 'POST':
            username = request.form['usuario']
            password = request.form['password']
            error = None
            if not username:
                error = 'Debes ingresar un usuario'
                flash(error)
                return render_template('iniciar.html')

            if not password:
                error = 'Debes ingresar una contraseña'
                flash(error)
                return render_template('iniciar.html')
            db = get_db()
            user = db.execute(
                'SELECT * FROM usuarios WHERE usuario= ?', (username, )).fetchone()
            db.close()
            if user is None:
                error = 'Usuario o contraseña inválidos'
                flash(error)
                return render_template('iniciar.html')
            else:
                store_password = user[10]
                result = check_password_hash(store_password, password)
                if result is False:
                    error = 'Usuario o contraseña inválidos'
                    flash(error)
                    return render_template('iniciar.html')
                else:
                    session.clear()
                    inicioS = False
                    session['user_id'] = user[0]
            adminL = user[13]
            if adminL == 'admin':
                admin = True
            if adminL == 'superAdmin':
                superAdmin = True
            inicioS = True
            return redirect(url_for('productos'))
        return render_template('iniciar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
    except Exception as e:
        return render_template('iniciar.html')


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('iniciar'))
        return view(**kwargs)
    return wrapped_view


def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None or admin == False:
            if superAdmin == True:
                return view(**kwargs)
            return redirect(url_for('inicio'))
        return view(**kwargs)
    return wrapped_view


def super_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None or superAdmin == False:
            return redirect(url_for('inicio'))
        return view(**kwargs)
    return wrapped_view


@app.route('/salir')
def salir():
    global inicioS
    global admin
    global superAdmin
    inicioS = False
    admin = False
    superAdmin = False
    session.clear()
    return redirect(url_for('inicio'))


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute(
            'SELECT * FROM usuarios WHERE id = ?', (user_id, )).fetchone()


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    try:
        if request.method == 'POST':
            nombre = request.form['nombre']
            apellido = request.form['apellido']
            cedula = request.form['cedula']
            correo = request.form['correo']
            sexo = request.form['sexo']
            fecha = request.form['fechaNacimiento']
            direccion = request.form['direccion']
            ciudad = request.form['ciudad']
            usuario = request.form['usuario']
            contrasena = request.form['contrasena']
            confirma = request.form['confirma']

            if not utils.isUsernameValid(nombre):
                error = "El nombre no es valido"
                flash(error)
                return render_template('registro.html')

            if not utils.isEmpty(fecha):
                error = "La fecha es invalida"
                flash(error)
                return render_template('registro.html')

            if not utils.isEmpty(direccion):
                error = "La direccion es invalida"
                flash(error)
                return render_template('registro.html')

            if not utils.isUsernameValid(apellido):
                error = "El apellido no es valido"
                flash(error)
                return render_template('registro.html')

            if not utils.isNumberValid(cedula):
                error = "El número de documento no es valido"
                flash(error)
                return render_template("registro.html")

            if not utils.isEmailValid(correo):
                error = "El correo no es valido"
                flash(error)
                return render_template('registro.html')

            if not utils.isPasswordValid(contrasena):
                error = "La contraseña no es valida"
                flash(error)
                return render_template('registro.html')

            if not utils.isPasswordValid(confirma):
                error = "La confirmación no es valida"
                if (contrasena != confirma):
                    error = "La contraseña debe coincidir con la confirmación"
                flash(error)
                return render_template('registro.html')

            error = None
            exito = False

            try:
                terminos = request.form['terminos']
            except Exception as e:
                e = "Debe aceptar los terminos y condiciones antes de avanzar"
                flash(e)
                return render_template("registro.html")
            db = get_db()

            demail = db.execute(
                'SELECT id FROM usuarios WHERE correo=?', (correo,)).fetchone()
            user = db.execute(
                'SELECT id FROM usuarios WHERE cedula=?', (cedula,)).fetchone()

            if user is not None:
                error = 'El usuario ya existe'.format(usuario)
                flash(error)

                return render_template('registro.html')

            if demail is not None:
                error = 'El usuario ya existe'.format(correo)
                flash(error)

                return render_template('registro.html')
            try:
                db.execute('INSERT INTO usuarios (nombre,apellido,cedula,correo,sexo,fecha_nacimiento,direccion,ciudad,usuario,contrasena) VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (nombre, apellido, cedula, correo, sexo, fecha, direccion, ciudad, usuario, generate_password_hash(contrasena)))
                db.commit()
                db.close()
                exito = True
                render_template('registro.html')
            except Exception as e:
                print(e)
            return redirect(url_for('iniciar'))
        return render_template('registro.html')
    except Exception as e:
        return render_template('registro.html')


@app.route('/recuperar', methods=['POST', 'GET'])
def recuperar():
    global recuperar
    try:
        if request.method == 'POST':
            email = request.form['email']
            error = None
            exito = False
            if not utils.isEmailValid(email):
                error = "El email no es valido"
                flash(error)
                return render_template('recuperar.html')
            db = get_db()
            validacion = db.execute(
                'SELECT correo FROM usuarios WHERE correo=?', (email,)).fetchone()
            if validacion is None:
                error = 'El usuario no existe'.format(email)
                flash(error)
                return render_template('recuperar.html')
            exito = True
            id_usuario = db.execute(
                'SELECT id FROM usuarios WHERE correo=?', (email,)).fetchone()
            id_usuario = str(id_usuario)
            id_usuario = id_usuario.replace('(', '')
            id_usuario = id_usuario.replace(')', '')
            id_usuario = id_usuario.replace("'", "")
            id_usuario = id_usuario.replace(",", "")
            id_usuario = id_usuario.replace('"', '')
            codigo = db.execute(
                'SELECT contrasena FROM usuarios WHERE correo=?', (email,)).fetchone()
            codigo = str(codigo)
            codigo = codigo.replace('(', '')
            codigo = codigo.replace(')', '')
            codigo = codigo.replace("'", "")
            codigo = codigo.replace(",", "")
            codigo = codigo.replace('"', '')
            db.execute(
                'UPDATE estadoCuenta SET codigo_seguridad = :nuevoCodigo WHERE id_usuarios = :id', {"nuevoCodigo": codigo, "id": id_usuario})
            recupera_contenido = (
                'Para restablecer tu contraseña ingresa al enlace y utiliza tu codigo de seguridad(recuerda usarlo sin espacios)\n\nCodigo:%s\n\nEnlace:%s') % (codigo, "link: localhost:5000/restablecer")
            yag.send(to=email, subject=tema_recupera,
                     contents=recupera_contenido)
            db.commit()
            db.close()
            flash('Hemos enviado un mensaje a su correo')
            return render_template('recuperar.html', inicioS=inicioS, exito=exito)
        return render_template('recuperar.html', inicioS=inicioS)
    except Exception as e:
        print(e)
        return render_template('recuperar.html', inicioS=inicioS)


@app.route('/restablecer', methods=['GET', 'POST'])
def restablecer():
    try:
        if request.method == 'POST':
            db = get_db()
            id_u = request.form['seguridad']
            nueva = request.form['nueva']
            confirma = request.form['confirma']
            validacion = db.execute(
                'SELECT codigo_seguridad FROM estadoCuenta WHERE codigo_seguridad=?', (id_u,)).fetchone()
            if validacion is None:
                error = "El codigo no es valido"
                flash(error, category="info")
                return render_template("restablecer.html")
            print(validacion)
            if not utils.isPasswordValid(nueva):
                error = "La contraseña no es valida"
                flash(error, category="info")
                return render_template("restablecer.html")
            if not utils.isPasswordValid(confirma):
                error = "La confirmación no es valida"
                if (nueva != confirma):
                    error = "La contraseña debe coincidir con la confirmación"
                flash(error, category="info")
                return render_template("restablecer.html")
            validacion = db.execute(
                'SELECT codigo_seguridad FROM estadoCuenta WHERE codigo_seguridad=?', (id_u,)).fetchone()
            id_usuario = db.execute(
                'SELECT id_usuarios FROM estadoCuenta WHERE codigo_seguridad=?', (id_u,)).fetchone()
            id_usuario = str(id_usuario)
            id_usuario = id_usuario.replace('(', '')
            id_usuario = id_usuario.replace(')', '')
            id_usuario = id_usuario.replace("'", "")
            id_usuario = id_usuario.replace(",", "")
            id_usuario = id_usuario.replace('"', '')
            db.execute(
                'UPDATE usuarios SET contrasena  = :nueva WHERE id = :id', {"nueva": generate_password_hash(nueva), "id": id_usuario})
            nuevaSeguridad = db.execute(
                'SELECT contrasena FROM usuarios WHERE id = :id', {"id": id_usuario}).fetchone()
            nuevaSeguridad = str(nuevaSeguridad)
            nuevaSeguridad = nuevaSeguridad.replace('(', '')
            nuevaSeguridad = nuevaSeguridad.replace(')', '')
            nuevaSeguridad = nuevaSeguridad.replace("'", "")
            nuevaSeguridad = nuevaSeguridad.replace(",", "")
            nuevaSeguridad = nuevaSeguridad.replace('"', '')
            db.execute(
                'UPDATE estadoCuenta SET codigo_seguridad = :nuevoCodigo WHERE id_usuarios = :id', {"nuevoCodigo": nuevaSeguridad, "id": id_usuario})
            db.commit()
            db.close()
            flash("Se ha cambiado su contraseña", category="success")
            return render_template("restablecer.html")
        return render_template("restablecer.html")
    except Exception as e:
        print(e)
        return render_template("restablecer.html")


@app.route('/productos', methods=['POST', 'GET'])
def productos():
    sql = "SELECT * FROM productos"
    db = get_db()
    cursor = db.cursor()
    cursor.execute(sql)
    productos = cursor.fetchall()
    db.close()
    return render_template("productos.html", inicioS=inicioS, productos=productos, superAdmin=superAdmin, admin=admin)


@app.route('/cambiar', methods=['GET', 'POST'])
@login_required
def cambiar():
    try:
        if request.method == 'POST':
            db = get_db()
            anterior = request.form['anterior']
            nueva = request.form['nueva']
            confirma = request.form['confirma']
            user = db.execute(
                'SELECT * FROM usuarios WHERE id= ?', (session['user_id'], )).fetchone()
            store_password = user[10]
            if not utils.isEmpty(anterior):
                error = "La contraseña anterior no es invalida"
                flash(error, category='info')
                return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
            result = check_password_hash(store_password, anterior)
            if result is False:
                error = 'La contraseña no coincide!'
                flash(error, category="info")
                return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
            if not utils.isPasswordValid(nueva):
                error = "La contraseña no es valida"
                flash(error, category="info")
                return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
            if not utils.isPasswordValid(confirma):
                error = "La confirmación no es valida"
                if (nueva != confirma):
                    error = "La contraseña debe coincidir con la confirmación"
                flash(error, category="info")
                return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
            db.execute(
                'UPDATE usuarios SET contrasena  = :nueva WHERE id = :id', {"nueva": generate_password_hash(nueva), "id": session['user_id']})
            db.commit()
            db.close()
            flash("Se ha cambiado su contraseña", category="success")
            return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
        return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)
    except Exception as e:
        print(e)
        return render_template('cambiar.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)


@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    db = get_db()
    id_user = g.user[0]
    nombre = g.user[1]
    apellido = g.user[2]
    sexo = g.user[5]
    fecha = g.user[6]
    direccion = g.user[7]
    ciudad = g.user[8]
    numeroCompras = db.execute(
        'SELECT acumuladoCompras FROM compras WHERE id_usuarios=?', (id_user,)).fetchone()
    bonos = db.execute(
        'SELECT numeroBonos FROM compras WHERE id_usuarios=?', (id_user,)).fetchone()
    try:
        if request.method == 'POST':
            nombreC = request.form['nombre']
            apellidoC = request.form['apellido']
            sexoC = request.form['sexo']
            fechaC = request.form['fechaNacimiento']
            direccionC = request.form['direccion']
            ciudadC = request.form['ciudad']
            if not utils.isEmpty(nombreC):
                error = "El nombre es invalido"
                flash(error, category='info')
                return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
            if not utils.isEmpty(apellidoC):
                error = "El apellido es invalido"
                flash(error, category='info')
                return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
            if not utils.isEmpty(sexoC):
                error = "El sexo es invalido"
                flash(error, category='info')
                return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
            if not utils.isEmpty(direccionC):
                error = "La dirección es invalida"
                flash(error, category='info')
                return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
            if not utils.isEmpty(ciudad):
                error = "La ciudad es invalida"
                flash(error, category='info')
                return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)

            db.execute(
                'UPDATE usuarios SET nombre = :nombre, apellido = :apellido, sexo = :sexo, fecha_nacimiento = :fecha, direccion = :direccion, ciudad = :ciudad WHERE id = :id', {"nombre": nombreC, "apellido": apellidoC, "sexo": sexoC, "fecha": fechaC, "direccion": direccionC, "ciudad": ciudadC, "id": id_user})
            db.commit()
            db.close()
            flash("Recargue la pagina para ver los cambios!", category="success")
            return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
        return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)
    except Exception as e:
        print(e)
    return render_template('perfil.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin, nombre=nombre, apellido=apellido, sexo=sexo, fecha=fecha, direccion=direccion, ciudad=ciudad, numeroCompras=numeroCompras, bonos=bonos)


@app.route('/eliminarCuenta', methods=['GET'])
@login_required
def eliminarCuenta():
    if request.method == 'GET':
        id_usuario = session['user_id']
        db = get_db()
        db.execute("DELETE FROM usuarios WHERE id= :id", {"id": id_usuario})
        db.commit()
        db.close()
    return render_template("index.html")


@app.route('/listaDeseos', methods=['GET', 'POST'])
@login_required
def listaDeseos():
    return render_template('listaDeseos.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)


@app.route('/carrito', methods=['GET', 'POST'])
@login_required
def carrito():

    return render_template('carrito.html', inicioS=inicioS, superAdmin=superAdmin, admin=admin)


@app.route('/herramientas', methods=['GET'])
@admin_required
def herramienta():
    return render_template('herramientas.html', superAdmin=superAdmin, admin=admin)


@app.route('/editar', methods=['POST', 'GET'])
@admin_required
def editar():
    try:
        if request.method == 'POST':
            try:
                db = get_db()
                usuarios = db.execute(
                    'SELECT * FROM usuarios WHERE rol = :rol', {"rol": "usuario"}).fetchall()
                for i in usuarios:
                    flash(i, category='info')
            except Exception as e:
                flash(e)
            try:
                db = get_db()
                id_req = request.form['id']
                casilla = request.form['casilla']
                nombre = request.form['nombre']
                usuarioCa = db.execute(
                    'SELECT * FROM usuarios WHERE id = :id', {"id": id_req}).fetchone()
                usuarioCa = list(usuarioCa)
                casilla = int(casilla)
                if utils.isEmpty(nombre) is True:
                    print(usuarioCa[casilla])
                    usuarioCa[casilla] = nombre
                    db.execute(
                        'UPDATE usuarios SET id = :id, nombre = :nombre, apellido=:apellido, cedula = :cedula, correo = :correo, sexo = :sexo, fecha_nacimiento = :fecha,direccion=:direccion,ciudad=:ciudad,usuario = :usuario, contrasena = :contrasena, acumulado_compras = :compras,bonos_acumulados=:bonos WHERE id = :id', {"id": usuarioCa[0], "nombre": usuarioCa[1], "apellido": usuarioCa[2], "cedula": usuarioCa[3], "correo": usuarioCa[4], "sexo": usuarioCa[5], "fecha": usuarioCa[6], "direccion": usuarioCa[7], "ciudad": usuarioCa[8], "usuario": usuarioCa[9], "contrasena": usuarioCa[10], "compras": usuarioCa[11], "bonos": usuarioCa[12], "id": id_req})
                    db.commit()
                    print("b")
                    flash("Se realizo la actualización de datos!",
                          category='success')
                    return render_template('editar.html', superAdmin=superAdmin, admin=admin)
            except Exception as e:
                print(e)
                return render_template('editar.html', superAdmin=superAdmin, admin=admin)
        return render_template('editar.html', superAdmin=superAdmin, admin=admin)
    except Exception as e:
        return render_template('editar.html', superAdmin=superAdmin, admin=admin)


@app.route('/superUser', methods=['GET', 'POST'])
@super_required
def superUser():
    try:
        if request.method == 'POST':
            nombre = request.form['nombre']
            apellido = request.form['apellido']
            cedula = request.form['cedula']
            correo = request.form['correo']
            sexo = request.form['sexo']
            fecha = request.form['fechaNacimiento']
            direccion = request.form['direccion']
            ciudad = request.form['ciudad']
            usuario = request.form['usuario']
            contrasena = request.form['contrasena']
            confirma = request.form['confirma']
            cargo = request.form['cargo']
            rol = request.form['rol']

            if not utils.isUsernameValid(nombre):
                error = "El nombre no es valido"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isEmpty(fecha):
                error = "La fecha es invalida"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isEmpty(direccion):
                error = "La direccion es invalida"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isUsernameValid(apellido):
                error = "El apellido no es valido"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isNumberValid(cedula):
                error = "El número de documento no es valido"
                flash(error,category="error")
                return render_template("superUser.html", superAdmin=superAdmin, admin=admin)

            if not utils.isEmailValid(correo):
                error = "El correo no es valido"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isPasswordValid(contrasena):
                error = "La contraseña no es valida"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            if not utils.isPasswordValid(confirma):
                error = "La confirmación no es valida"
                if (contrasena != confirma):
                    error = "La contraseña debe coincidir con la confirmación"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)
            if not utils.isEmpty(cargo):
                error = "El cargo es invalido"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)
            if not utils.isEmpty(rol):
                error = "El rol es invalido"
                flash(error,category="error")
                return render_template('superUser.html', superAdmin=superAdmin, admin=admin)

            error = None
            exito = False

            try:
                terminos = request.form['terminos']
            except Exception as e:
                e = "Debe aceptar los terminos y condiciones antes de avanzar"
                flash(e,category="error")
                return render_template("superUser.html")
            db = get_db()

            demail = db.execute(
                'SELECT id FROM usuarios WHERE correo=?', (correo,)).fetchone()
            user = db.execute(
                'SELECT id FROM usuarios WHERE cedula=?', (cedula,)).fetchone()

            if user is not None:
                error = 'El usuario ya existe'.format(usuario)
                flash(error,category="error")
                return render_template('superUser.html')

            if demail is not None:
                error = 'El usuario ya existe'.format(correo)
                flash(error,category="error")

                return render_template('superUser.html')
            try:
                db.execute('INSERT INTO usuarios (nombre,apellido,cedula,correo,sexo,fecha_nacimiento,direccion,ciudad,usuario,contrasena,cargo,rol) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (nombre, apellido, cedula, correo, sexo, fecha, direccion, ciudad, usuario, generate_password_hash(contrasena), cargo, rol))
                db.commit()
                db.close()
                exito = True
                flash("Usuario creado con exito!",category="success")
                render_template('superUser.html',
                                superAdmin=superAdmin, admin=admin)
            except Exception as e:
                print(e)
        return render_template('superUser.html', superAdmin=superAdmin, admin=admin)
    except Exception as e:
        return render_template('superUser.html', superAdmin=superAdmin, admin=admin)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
