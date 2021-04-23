import difflib

from flask import Flask, render_template, url_for, request, redirect, make_response, jsonify, flash
import datetime
from time import time
import json
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fdgdfgdfggf786hfg6hfg6h7f'
app.config['TEMPLATES_AUTO_RELOAD'] = True

try:
    users = json.loads(open('users.json', 'r').read())
except:
    users = {}

try:
    posts = json.loads(open('posts.json', 'r').read())
except:
    posts = {}

try:
    messages = json.loads(open('messages.json', 'r').read())
except:
    messages = []

try:
    troubles = json.loads(open('troubles.json', 'r').read())
except:
    troubles = []


def save_users():
    open('users.json', 'w').write(json.dumps(users))


def save_posts():
    open('posts.json', 'w').write(json.dumps(posts))


def save_messages():
    open('messages.json', 'w').write(json.dumps(messages))


def save_troubles():
    open('troubles.json', 'w').write(json.dumps(troubles))


def check_user(req):
    if not req.cookies.get('login') or not req.cookies.get('user_secret') or req.cookies.get('login') not in users or \
            users[req.cookies.get('login')]['user_secret'] != request.cookies.get('user_secret'):
        return False

    return True


@app.route("/", methods=['GET'])
@app.route("/home", methods=['GET'])
def home():
    return render_template("home.html", authed=check_user(request))


@app.route("/friends", methods=["GET"])
def friends():
    if not check_user(request):
        return redirect('/login')

    search_login = request.values.get('login')

    searchlist = list(users.keys())

    if request.cookies.get('login') in searchlist:
        del searchlist[searchlist.index(request.cookies.get('login'))]
    no_res = {}
    for key, el in users.items():
        if key not in users[request.cookies.get('login')]['friends'] and key != request.cookies.get('login'):
            no_res[key] = el
    return render_template("friends.html", friends_name=searchlist,
                           authed=check_user(request), users=users[request.cookies.get('login')]['friends'],
                           no_friends_name=no_res)


@app.route("/friends", methods=["POST"])
def friends_post():
    if not check_user(request):
        return redirect('/login')

    search_login = request.values.get('login')
    if search_login == '' or not search_login:
        return redirect('/friends')

    searchlist = difflib.get_close_matches(search_login,
                                           list(users.keys()), cutoff=.7)

    if request.cookies.get('login') in searchlist:
        del searchlist[searchlist.index(request.cookies.get('login'))]

    return render_template('friends.html', friends_name=searchlist, search=search_login,
                           authed=check_user(request), users=users[request.cookies.get('login')]['friends'])


@app.route("/friends_add", methods=["POST"])
def friends_add():
    friend_name = request.form["friends"]
    users[request.cookies.get('login')]['friends'].append(friend_name)
    users[friend_name]['friends'].append(request.cookies.get('login'))
    messages.append({
        'peers': [request.cookies.get('login'), friend_name],
        'messages': [],
        'type': "private"
    })
    save_users()
    save_messages()
    return redirect("/friends")


@app.route("/friends_messages", methods=["GET"])
def friends_messages():
    second_user = request.values.get('second_user')
    print(request.cookies.get('login'))
    for chat in messages:
        if chat['type'] == "private":
            if request.cookies.get('login') in chat['peers'] and second_user in chat['peers']:
                return render_template("friends_messages.html", authed=check_user(request), second_user=second_user,
                                       chat=chat['messages'], username=request.cookies.get('login'))

    return 'Forbidden', 403


@app.route("/friends_messages", methods=["POST"])
def friends_messages_post():
    global messages
    second_user = request.form["second_user"]
    message = request.form["message"]
    for i in range(len(messages)):
        if messages[i]['type'] == "private":
            if request.cookies.get('login') in messages[i]['peers'] and second_user in messages[i]['peers']:
                messages[i]['messages'].append({
                    'contents': message,
                    'user': request.cookies.get('login')
                })
                save_messages()
                return render_template("friends_messages.html", authed=check_user(request), second_user=second_user,
                                       chat=messages[i]['messages'], username=request.cookies.get('login'))

    return 'Forbidden', 403


@app.route("/contacts", methods=["GET"])
def contacts():
    if not check_user(request):
        return redirect('/login')
    return render_template("contacts.html", authed=check_user(request))


@app.route("/contacts", methods=["POST"])
def contacts_post():
    if not check_user(request):
        return redirect('/login')
    email = request.form["email"]
    content = request.form["content"]
    troubles.append({
        'email': email,
        'content': content
    })
    save_troubles()
    return render_template("home.html", authed=check_user(request))


@app.route("/projects", methods=["GET"])
def projects():
    if not check_user(request):
        return redirect('/login')

    res = {}
    for key, el in posts.items():
        res[key] = el
    no_res = {}
    for key, el in posts.items():
        if key not in users[request.cookies.get('login')]['projects']:
            no_res[key] = el
    return render_template("projects.html", projects_list=res,
                           authed=check_user(request),
                           user_projects=users[request.cookies.get('login')]['projects'], no_projects_list=no_res)


def sequence_matcher(input_dict, search, column, cutoff, n=0):
    matches = list()
    for key, value in input_dict.items():
        if n > 0 and len(matches) > n:
            break

        if difflib.SequenceMatcher(None, search, value[column]).ratio() >= cutoff:
            matches.append([key, value])
    return matches


@app.route("/projects", methods=['POST'])
def projects_post():
    if not check_user(request):
        return redirect('/login')

    title = request.values.get('title')

    if title == '' or not title:
        return redirect('/projects')
    print(sequence_matcher(posts, title, 'title', .7))

    """res = {}
    for key, el in posts.items():
        for name in sequence_matcher(posts, title, 'title', .7):
            if el['title'] == name:
                res[key] = el
    print(res)"""
    no_res = {}
    for key, el in posts.items():
        if key not in users[request.cookies.get('login')]['projects']:
            no_res[key] = el
    return render_template('projects.html', projects_list=dict(sequence_matcher(posts, title, 'title', .7)),
                           search=title, no_projects_list=no_res,
                           authed=check_user(request), user_projects=users[request.cookies.get('login')]['projects'])


@app.route("/projects_add", methods=['POST'])
def projects_add():
    project_id = request.form["project"]
    users[request.cookies.get('login')]['projects'].append(project_id)
    for chat in messages:
        if chat['type'] == 'project':
            if chat['key'] == project_id:
                chat['peers'].append(request.cookies.get('login'))
    save_users()
    return redirect("/projects")


@app.route("/create_projects", methods=["GET"])
def create_projects():
    if not check_user(request):
        return redirect('/login')

    return render_template("create_projects.html", authed=check_user(request))


@app.route("/create_projects", methods=["POST"])
def create_projects_post():
    if not check_user(request):
        return redirect('/login')
    title = request.form["title"]
    limit = request.form["limit"]
    contents = request.form["contents"]
    if not title or not limit or not contents:
        return 'Some of the fields are empty', 400

    post_id = hashlib.sha256(str(time()).encode('utf-8')).hexdigest()

    posts[post_id] = {
        'title': title,
        'limit': limit,
        'contents': contents,
        'creator': request.cookies.get('login'),
        'users': request.cookies.get('login'),
        'date': str(datetime.datetime.now()),
        'post_id': post_id
    }
    users[request.cookies.get('login')]['projects'].append(post_id)
    messages.append({
        'type': 'project',
        'peers': [request.cookies.get('login')],
        'key': post_id,
        'messages': []
    })
    save_users()
    save_posts()
    save_messages()
    return render_template("projects.html", authed=check_user(request))


@app.route("/project_messages", methods=["GET"])
def project_messages():
    project_id = request.values.get('project_id')
    for chat in messages:
        if chat['type'] == "project":
            if chat['key'] == project_id:
                return render_template("project_messages.html", authed=check_user(request), project_id=project_id,
                                       chat=chat['messages'], username=request.cookies.get('login'))

    return 'Forbidden', 403


@app.route("/project_messages", methods=["POST"])
def project_messages_post():
    global messages
    project_id = request.form['project_id']
    message = request.form["message"]
    for chat in messages:
        if chat['type'] == "project":
            if project_id == chat['key']:
                chat['messages'].append({
                    'contents': message,
                    'user': request.cookies.get('login')
                })
                save_messages()
                return render_template("project_messages.html", authed=check_user(request), project_id=project_id,
                                       chat=chat['messages'], username=request.cookies.get('login'))

    return 'Forbidden', 403


@app.route("/saved")
def saved():
    res = {}
    if check_user(request):
        for key, post in posts.items():
            if post['creator'] in users[request.cookies.get('login')]['friends']:
                res[key] = post
        return render_template("saved.html", authed=check_user(request), res=res,
                               user_projects=users[request.cookies.get('login')]['projects'])
    else:
        return render_template("regs.html", authed=check_user(request))


@app.route("/about")
def about():
    return "It's SOOON"


@app.route("/logout")
def logout():
    resp = make_response(redirect('/home'))
    resp.set_cookie('login', '', expires=0)
    resp.set_cookie('user_secret', '', expires=0)
    return resp


@app.route("/regs", methods=['GET'])
def regs():
    return render_template("regs.html", authed=check_user(request))


@app.route("/regs", methods=['POST'])
def regs_post():
    email = request.form["email"]
    password = request.form["password"]
    login = request.form["login"]
    if email == '' or password == '' or login == '':
        flash('Заполните все поля.')
        return render_template("regs.html")
    if login in users:
        flash('Пользователь с этим именем уже существует.')
        return render_template("regs.html")

    for _, data in users.items():
        if data['email'] == email:
            flash('Пользователь с этой почтой уже существует.')
            return render_template("regs.html")

    users[login] = {
        'password': password,
        'email': email,
        'user_secret': hashlib.sha256(str(time()).encode('utf-8')).hexdigest(),
        'friends': [],
        'projects': []
    }
    save_users()
    for user, data in users.items():
        if user == login and data['password'] == password or data['email'] == login and data['password'] == password:
            resp = make_response(redirect('/home'))
            resp.set_cookie('login', login, path='/')
            resp.set_cookie('user_secret', data['user_secret'], path='/')
            return resp


@app.route('/login', methods=['GET'])
def login():
    return render_template("login.html", authed=check_user(request))


@app.route('/login', methods=['POST'])
def login_post():
    login = request.form.get('login')
    password = request.form.get('password')
    if login == '' or password == '':
        flash('Заполните все поля.')
        return render_template("login.html")
    for user, data in users.items():
        if user == login and data['password'] == password or data['email'] == login and data['password'] == password:
            resp = make_response(redirect('/home'))
            resp.set_cookie('login', login, path='/')
            resp.set_cookie('user_secret', data['user_secret'], path='/')
            return resp

    flash('Логин/Email или пароль неправильно заполнены.')
    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
