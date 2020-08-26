from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_mysqldb import MySQL
import bcrypt

app = Flask(__name__)
#llave secreta para sesiones
app.secret_key = "Lanochemasoscura"
#Encriptamiento
dataEncrypt = bcrypt.gensalt()

#Database Config
app.config["MYSQL_HOST"] = "127.0.0.1"
app.config["MYSQL_PORT"] = 3307
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "Edepecel638"
app.config["MYSQL_DB"] = "flask_app"
mysql = MySQL(app)




@app.route('/')
def main():
    #Con esto comprobarmos la sesion y evitamos volver a pasar por el login
    if "nombre" in session:
        return render_template('inicio.html')
    else:
        return render_template("ingresar.html")


@app.route('/inicio')
def inicio():
    if "nombre" in session:
        return render_template('inicio.html')
    else:
        return render_template('ingresar.html')


@app.route('/registrar', methods = ["GET","POST"])
def registrar():
    if(request.method == "GET"):
        #validacion sobre el metodo get forzado
        if "nombre" in session:
            return render_template('inicio.html')
        else:
            return render_template("ingresar.html")
    else:
        #obtiene los datos
        nombre = request.form['nmNombreRegistro']
        email = request.form['nmEmailRegistro']
        password = request.form['nmPasswordRegistro']
        password_encode = password.encode('utf-8')
        password_encrypt = bcrypt.hashpw(password_encode, dataEncrypt)
        print("insertando: ")
        print("Password_encode: " , password_encode)
        print("Password_encriptado: ", password_encrypt)

        query = "INSERT INTO LOGIN(EMAIL, PASSWORD, NOMBRE) VALUES (%s, %s, %s)"
        cursor = mysql.connection.cursor()
        cursor.execute(query,(email, password_encrypt, nombre))
        mysql.connection.commit()

        #registro de sesion 
        session['nombre'] = nombre
        session['email'] = email

        return redirect(url_for('inicio'))


@app.route('/ingresar', methods = ['GET','POST'])
def ingresar():
    if(request.method == 'GET'):
        if 'nombre' in session:
            return render_template('inicio.html')
        else:
            return render_template('ingresar.html')
    else:
        email = request.form['nmEmailLogin']
        password = request.form['nmPasswordLogin']
        password_encode = password.encode('utf-8')

        cursor = mysql.connection.cursor()
        query = "SELECT EMAIL, PASSWORD, NOMBRE FROM LOGIN WHERE EMAIL = %s"
        cursor.execute(query,[email])
        usuario = cursor.fetchone()
        cursor.close()

        #comprobando la obtencion de datos
        if(usuario != None):
            password_encriptado_encode = usuario[1].encode()

            print("Password_encode: ", [password_encode])
            print("Password_encriptado_encode: ", password_encriptado_encode)

            #comprueba el passsword
            if (bcrypt.checkpw(password_encode,password_encriptado_encode)):
                #almacena la sesion
                session['nombre'] = usuario[2]
                session['email'] = email

                return redirect(url_for('inicio'))
            else:
                flash("El password no es correcto", "alert-warning")
                return render_template('ingresar.html')

        else:
            print('El usuairo no existe')
            flash("El correo no existe",'alert-warning')
            return render_template('ingresar.html')



@app.route('/salir')
def salir():
    session.clear()
    return redirect(url_for('ingresar'))



if __name__ == "__main__":
    app.run(debug = True)