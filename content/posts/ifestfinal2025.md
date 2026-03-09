---
title: "ifest CTF 2025"
description: "Local onsite Indonesia CTF"
date: 2025-05-24
tags: ["Web Exploitation"]
categories: ["Writeups"]
showTableOfContents: true
draft: false
---

### Team : @PETIR
### rank : ?

# Title : Web v2
```
Bruh, someone just hacked my website. And now im pretty sure no one will hack my website again!

http://url/login

Author: daffainfo
```

Here is the challenge provided source code

```python
app = Flask(__name__)
app.secret_key = secrets.token_hex(64)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.String(1), default='0')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        data['password'] = hash_password(data['password'])


        user = User(**data)
        db.session.add(user)
        db.session.commit()


        return redirect('/login')
    return render_template('register.html')
```

From the code above, we know that all users have three parameters we can use: username, password, and is_admin.

The danger here is that there's no check at the /register endpoint that allows users to freely change the is_admin value.

So, we can create an account simply by adding "is_admin": "1" to the /register JSON string, and we'll get an admin account.

Even though we already have an admin account, it turns out that when we enter /admin/fetch we are still given a forbidden message, this is really strange, right WKWK, so we immediately read the source code again.

Here is the challenge provided nginx source code

```
events {}


http {
    server {
        listen 80;


        location = /admin/fetch {
            deny all;
        }


        location = /admin/fetch/ {
            deny all;
        }


        location = /internal {
            deny all;
        }


        location = /internal/ {
            deny all;
        }


        location / {
            proxy_pass http://ctfapp:1337;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

If we read it correctly we can realize that in the nginx configuration, we are denied almost all the given endpoints, but if only with nginx we can bypass this by adding a byte that will not be considered by the server but will still go to /admin/fetch.

So according to the source above, we can add \xa0 to bypass the deny all nginx.

Now the challenge is before getting the flag

```python
@app.route('/admin/fetch', methods=['GET', 'POST'])
def admin_fetch():
    if 'user_id' not in session:
        return redirect('/login')


    user = db.session.get(User, session['user_id'])
    if user.is_admin != '1':
        return "You are not authorized.", 403


    result = None
    if request.method == 'POST':
        data = request.get_json()
        url = data.get('url')


        parsed_url = urlparse(url)


        if parsed_url.hostname != 'daffainfo.com':
            result = "Error: Only URLs with hostname 'daffainfo.com' are allowed."
        else:
            try:
                resp = requests.get(url, timeout=5)
                result = resp.text
            except Exception as e:
                result = f"Error fetching URL: {str(e)}"


    return render_template('fetch.html', result=result)
```

So, the important thing is only the

urlparse(url)

and hostname checking part. So, essentially, we need a way to trick urlparse() into getting daffainfo.com and a fixed URL.

http://localhost:\@daffainfo.com/../internal

This will trick the server into going to localhost/internal, but urlparser() will still retrieve the value at @daffainfo.com. However, on the server, we need to provide \\ to prevent Nginx from erroring.

![Description of image](/images/ifest2025.png)

{{< alert icon="check-circle" cardColor="#10b981" >}}
**Flag :** `IFEST13{a0526f70f53e2aa1d395ac02b7653498}`
{{< /alert >}}

### References :

https://book.hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html
