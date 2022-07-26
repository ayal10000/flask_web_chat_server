__author__ = "AYAL MERGUI"

# modules
from flask import Flask, redirect, url_for, render_template, request, session, flash, send_from_directory
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from datetime import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
import sqlite3
import hashlib
import os
import base64
import glob
import threading

# flask&flask_socketio and database of usernames
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANBOMQo9wX55+w1ijEaPoYRP2T4BOjoFv3ma0QWqYYQ8FH0z14Zc
B/jb0j2PWpyNcsUUBovj+yWxQnQohCck64kCAwEAAQJBAL4s9PbNpO9MfFkfBMSS
8zoyEDtcsYUxpDtojbandDpdXfvn5D279QaOVLb1C3DgQTTEmroYB8dbeZBc5YJC
2AECIQDqyUn68ehRcx/EyLMUB1IuckZBWCIApgfn7phgVwSwiQIhAOMgY4bN+xrx
UV15Ian4ZbkME1IbAvDPcWuNGHxdsaMBAiBoz0K/S44yDfp4lj+bCUmeglTqhrVn
JLcSymgrWa02QQIhAMJFvPvcilGkYl1atCHHt3LN0mTjd+N0/OXq3SvblIsBAiAc
8RzaV1GmjMEJxw9vM/tQwQg0kyAPlITMRXnwGA6E0A==
-----END RSA PRIVATE KEY-----"""
rsa = RSA.importKey(private_key)
cipher = PKCS1_v1_5.new(rsa)
font = ""
size = ""
color_choice = ""
zz = 0
found_first_time = False
decryption = ""
jj = 0
index_Sending = 0
other_user = ""
users_couple = ""
dict_of_msg = {}
app = Flask(__name__)
app.secret_key = "00010101010110"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users3.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
room = ""
app.permanent_session_lifetime = timedelta(minutes=10)
db = SQLAlchemy(app)
db_chats = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins='*')
list_user_to_user = []
list_decrypt = ["base64", "sha1", "md5"]
list_online_users = []
LOCK_flask = threading.Lock()



# encrypt from string to base64
def encrypt(msg):
    ciphertext = cipher.encrypt(msg.encode('utf8'))
    return base64.b64encode(ciphertext).decode('ascii')


# decrypt from base64 to regular string
def decrypt(msg):
    ciphertext = base64.b64decode(msg.encode('ascii'))
    plaintext = cipher.decrypt(ciphertext, b'DECRYPTION FAILED')
    return plaintext.decode('utf8')


# define the list of users pairs
def define_user_to_user():
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    for row in cursor:
        list_user_to_user.append(user_talk(row[0], None,""))

# append to the list new client
def define_user_to_user_new_user(number_of_user):
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    list_user_to_user.append(user_talk(number_of_user, None,""))

# delete session_id attribute from the user
def delete_session_id(sid1):
    for i in range(0,len(list_user_to_user)):
        if list_user_to_user[i].get_session_id() == sid1:
            list_user_to_user[i].set_session_id("")
            print("sucess delete session_id")

def define_history():
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    # check if the name is already exist
    for row in cursor:
        dict_of_msg[row[1]] = []


# encrypt to base64
def Encode_base64(msg):
    message_bytes = msg.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    return base64_message

#decrypt from base64 to regular string
def Decode_base64(msg):
    base64_bytes = msg.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    return message



# find the specific user on list according to his id
def Find_specific_user(number):
    for i in range(len(list_user_to_user)):
        if list_user_to_user[i].get_name_user() == number:
            return list_user_to_user[i]




# render the chat html page
@app.route("/chats")
def home2():
    return render_template("index.html",name_user = Find_name(session["user"]), name2=Find_name(other_user))


# this class define 2 users platform and session_id (for identify socket) of the "name" attribute
class user_talk():
    def __init__(self, name, other_user,session_id):
        self.name = name
        self.other_user = other_user
        self.session_id = session_id

    def __str__(self):
        return "name_user: " + str(self.name) + " other user: " + str(self.other_user)

    def get_name_user(self):
        return self.name

    def get_name_other_user(self):
        return self.other_user

    def set_name_user(self, name):
        self.name = name

    def set_name_other_user(self, other_user):
        self.other_user = other_user

    def set_session_id(self,session_id):
        self.session_id = session_id

    def get_session_id(self):
        return self.session_id


# class of database of users
class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    passw = db.Column(db.String(100))
    color = db.Column(db.String(100))

    def __init__(self, name, passw, color):
        self.name = name
        self.passw = passw
        self.color = color

    def set_color(self, color):
        self.color = color

    def get_color(self):
        return self.color

# find id of user according to his name
def Find_id(name):
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    for row in cursor:
        if row[1] == name:
            return row[0]


# find name of user according to his id on sql table
def Find_name(id):
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    for row in cursor:
        if row[0] == id:
            return row[1]
    return 0


# present the home page
@app.route("/", methods=["POST", "GET"])
def home():
    print("welcome to home page")
    if request.method == "GET":
        print("comehere")
    try:
        print("user" in session)
        print(session["user"])
        if "user" in session:
            if Find_name(session["user"]) not in list_online_users:
                session.pop("user",None)
            else:
                return render_template("error_screen.html",file_name= "3")
        if "destroy" in session:
            print("destroy in session")
            session.pop("user",None)
            session.pop("destroy",None)

    except:
        print("errrrrr!!!!!!!")
    return render_template("base.html")


# sign up function
@app.route("/signup", methods=["POST", "GET"])
def sign_up():
    print("welcome to sign up")
    found = True
    if request.method == "POST":
        session.permanent = True
        user = request.form["nm"]
        session["user"] = user

        found_user = users.query.filter_by(name=user).first()
        print("------------------")
        print(found_user)
        print("---------------------------")
        conn = sqlite3.connect('users3.sqlite3')
        cursor = conn.execute("SELECT id, name,passw,color from USERS")

        # check if the name is already exist
        for row in cursor:
            if row[1] == request.form["nm"] or row[2] == Encode_base64(request.form["pw"]):
                found = False

        if found == False:
            flash("username or password are in using of other user", "error")
            return render_template("base2.html",type_of_sign = "Sign Up")


        else:
            usr = users(request.form["nm"], Encode_base64(request.form["pw"]), "#000000")
            db.session.add(usr)
            db.session.commit()
            flash("Login and signup  successful!", "error")
            session["user"] = Find_id(session["user"])
            define_user_to_user_new_user(session["user"])
            list_online_users.append(Find_name(session["user"]))
            return redirect(url_for("check_user_talk"))
    return render_template("base2.html",type_of_sign = "Sign Up")


# login function
@app.route("/login", methods=["POST", "GET"])
def login():
    found = True
    if request.method == "POST":
        session.permanent = True

        user = request.form["nm"]
        session["user"] = user
        print(request.form["nm"])
        print(request.form["pw"])

        found_user = users.query.filter_by(name=user).first()

        conn = sqlite3.connect('users3.sqlite3')
        cursor = conn.execute("SELECT id, name,passw,color from USERS")
        index_password = 0
        # check the name and password are correct or incorrect
        for row in cursor:
            if row[1] == request.form["nm"] and row[2] == Encode_base64(request.form["pw"]):
                index_password = row[2]
                found = False
                break

        if found == True:
            print("wrong details")
            flash("username or password are incorrect", "error")
            return render_template("base2.html",type_of_sign = "Login")
        if request.form["nm"] in list_online_users:
            print("wrong details")
            flash("this user also login on other device", "error")
            return render_template("base2.html", type_of_sign="Login")
        list_online_users.append(request.form["nm"])
        session["user"] = Find_id(session["user"])
        print("||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
        print("your password encrypt is: ", index_password)
        print("your password decrypt is", Decode_base64(index_password))
        if Find_name(session["user"]) == "admin":
            return redirect(url_for("delete_users"))
        print("your password encrypt is: ",index_password)
        print("your password decrypt is",Decode_base64(index_password))
        return redirect(url_for("check_user_talk"))
    else:
        if "user" in session:
            return "400 wrong because other user"
            return redirect(url_for("user"))
        return render_template("base2.html",type_of_sign = "Login")


# this function give to admin the permission to delete users from the system
@app.route("/admin_delete", methods=["POST", "GET"])
def delete_users():
    if request.method == "POST":
        name_to_delete = request.form["name2"]
        try:
            if name_to_delete!= "":
                # delete the user from username database
                sql_query = "DELETE FROM USERS WHERE name = " + "'" + name_to_delete + "'"
                conn = sqlite3.connect('users3.sqlite3')
                cursor = conn.execute("SELECT id, name,passw,color from USERS")
                print(sql_query)
                id_to_delete = Find_id(name_to_delete)
                cur = conn.cursor()
                cur.execute(sql_query)
                conn.commit()
                # delete the user from chats history database
                sql_query = "DELETE FROM chat WHERE name_from = " + "'" + str(id_to_delete) + "'"
                conn = sqlite3.connect('chats_21.sqlite3')
                cursor = conn.execute("SELECT id, name_from,name_to,info,time from chat")
                print(sql_query)
                cur = conn.cursor()
                cur.execute(sql_query)
                conn.commit()
                sql_query = "DELETE FROM chat WHERE name_to = " + "'" + str(id_to_delete) + "'"
                print(sql_query)
                cur = conn.cursor()
                cur.execute(sql_query)
                conn.commit()
                color = ""
                for row in cursor:
                    if row[0] == session["user"]:
                        color = row[3]
                        break
        except Exception as e:
            print(e)
        return redirect(url_for("update_user_name"))

    else:
        conn = sqlite3.connect('users3.sqlite3')
        cursor = conn.execute("SELECT id, name,passw,color from USERS")

        # check the name and password are correct or incorrect
        color = ""
        list_of_members = []
        list_of_members.append("")
        for row in cursor:
            list_of_members.append(row[1])
            if row[0] == session["user"]:
                color = row[3]
        flash("username or password are incorrect", "error")
        print(list_of_members)
        print("---------------------")
        return render_template("delete_users.html",users2 = list_of_members)



# this function get the permission to admin to change users names
@app.route("/update_user_name", methods=["POST", "GET"])
def update_user_name():
    if request.method == "POST":
        current_name = request.form["this_nm"] # privious name
        next_name = request.form["new_nm"] # new name

        try:
            sql_query = "UPDATE USERS SET name = " + '"' + next_name + '"' + " where name = " + '"' + current_name + '"'
            conn = sqlite3.connect('users3.sqlite3')
            cursor = conn.execute("SELECT id, name,passw,color from USERS")
            print(sql_query)
            if find_if_exist(current_name) == True:
                if find_if_exist(next_name) == False:
                    del dict_of_msg[current_name]
                    dict_of_msg[next_name] = []
                    #update the username on database
                    cur = conn.cursor()
                    cur.execute(sql_query)
                    conn.commit()


        except Exception as e:
            print(e)
        return redirect(url_for("check_user_talk"))

    else:
        return render_template("update_username.html")

# this function check if the usesr with this name is exist on database
def find_if_exist(name):
    conn = sqlite3.connect('users3.sqlite3')
    cursor = conn.execute("SELECT id, name,passw,color from USERS")
    for row in cursor:
        if row[1] == name:
            return True
    return False


# this function render and present html choice screen to which client you want to talk
@app.route("/check_user", methods=["POST", "GET"])
def check_user_talk():
    #global vars
    global other_user
    global decryption
    global color_choice
    global font
    global size
    # end of global vars
    try:
        print("the session of user is: ",session["user"])
    except:
        print("no session user")
    if request.method == "POST":
        session.permanent = True
        found = False
        name_other_user = (request.form["name2"]).split()[0]
        # export from html form the design chocies of user
        font = request.form["font2"]
        size = request.form["size2"]
        color_choice = request.form["colorPicker"]
        decryption = ""
        conn = sqlite3.connect('users3.sqlite3')
        cursor = conn.execute("SELECT id, name,passw,color from USERS")
        found_user = users.query.filter_by(name=Find_name(session["user"])).first()
        print("----------------")
        print(type(session["user"]))
        print(found_user)
        print("------------------")
        # update color bubble background choice
        sql_query = "UPDATE USERS SET color = " + '"' + color_choice + '"' + " where id = " + str(session["user"])
        print(sql_query)
        cur = conn.cursor()
        cur.execute(sql_query)
        conn.commit()
        for row in cursor:
            print(row[1])
            if row[1] == name_other_user:
                found = True
                break

        if found == True:
            other_user = name_other_user
            other_user = Find_id(other_user)
            Find_specific_user(session["user"]).set_name_other_user(other_user)
            return redirect(url_for("home2"))
        else:
            print("we dont have people in this name")
            flash("username or password are incorrect", "error")
            conn = sqlite3.connect('users3.sqlite3')
            cursor = conn.execute("SELECT id, name,passw,color from USERS")

            # check the name and password are correct or incorrect
            color = ""
            list_of_members = []
            for row_check in cursor:
                list_of_members.append(row_check[1] + determine_time_send(session["user"], row_check[0]))
                if row_check[0] == session["user"]:
                    color = row_check[3]

            flash("username or password are incorrect", "error")
            print(list_of_members)
            print("---------------------")
            return render_template("verify_user.html", color_of_uesr='<option value="volvo">volvos</option>',
                                   users2=list_of_members, my_x="<option value=\"volvo\">volvo</option>",my_username = Find_name(session["user"]))


    else:
        conn = sqlite3.connect('users3.sqlite3')
        cursor = conn.execute("SELECT id, name,passw,color from USERS")

        # check the name and password are correct or incorrect
        color = ""
        list_of_members = []
        for row_check in cursor:
            list_of_members.append(row_check[1] + determine_time_send(session["user"], row_check[0]))
            if row_check[0] == session["user"]:
                color = row_check[3]
        return render_template("verify_user.html", color_of_uesr=color, users2=list_of_members,my_username = Find_name(session["user"]))


# help function to the function above, this function get the info about last time message between user_1 and user_2
def determine_time_send(user_1,user_2):
    conn = sqlite3.connect('chats_21.sqlite3')
    try:
        cursor2 = conn.execute("CREATE TABLE chat( id INTEGER, name_from TEXT,  name_to TEXT, info TEXT, time TEXT)")
    except Exception as e:
        print(e)
    cursor = conn.execute("SELECT id,name_from,name_to,info,time from chat")
    time_send = ""
    for row in cursor:

        if (row[1]==str(user_1) and row[2]==str(user_2)):
            time_send = row[4]
        if row[1]==str(user_2) and row[2]==str(user_1):
            time_send =row[4]
    if time_send == "":
        return " last message time:No messages yet"
    return " last message time:"+time_send


# this functions listen to the event when client leavre the chat screen
@socketio.on('client_disconnecting')
def disconnected_close_tab(msg):
    print("you closed the tab")
    print(request.path)
    print(request.sid)
    session["is_connect"] = True
    delete_session_id(request.sid)


# this function listen to all event of disconnectiong and include close tab of client
@app.route("/chats", methods=["POST", "GET"])
@socketio.on('disconnect')
def disconnect():
    rule = request.url_rule
    print("disconnect function")
    print(request.sid)
    print(request.path)
    if "is_connect" in session:
        print("now an then, past and future")

    else:
        #close tab of client
        delete_session_id(request.sid)
        try:
            list_online_users.remove(Find_name(session["user"]))
            print(list_online_users)
        except:
            print("no session here!!!!!!!!!!!!!!!!!!")
        print("you pop because close tab")
        print("user" in session)
        session.clear()
        print("user" in session)
        session["destroy"] = True



# this function send images to the clients
@app.route("/chats", methods=["POST", "GET"])
@socketio.on('img')
def take_care_img(msg):
    global zz
    try:
        print("image image image")

        conn = sqlite3.connect('chats_21.sqlite3')
        try:
            cursor2 = conn.execute("CREATE TABLE chat( id INTEGER, name_from TEXT,  name_to TEXT, info TEXT, time TEXT)")
        except Exception as e:
            print(e)

        cursor = conn.execute("SELECT id,name_from,name_to,info,time from chat")
        id = search_id() # export the id of message from sql file
        zz = zz + 1
        if zz == 2:
            print("come")
        if id != "L":
            id = id + 1
        else:
            id = 0
        print(type(msg))

        type_of_file = msg.split(";base64,")[0].split("/")[1]
        print(type_of_file)
        #decode the file that sent of base64 format
        msg = base64.b64decode(msg.split("base64,")[1])
        print("-----------------------")
        print(len(msg))
        print("-----------------------------------")
        print("----------------------")
        LOCK_flask.acquire()
        # create a png/jpeg file and write into it
        with open("static/images/" + str(id) + "." + type_of_file, "wb") as file_handle:
            file_handle.write(msg)
        LOCK_flask.release()

        today = datetime.now()
        dt_string = today.strftime("%d/%m/%Y %H:%M:%S")
        # send time-send and the image himself
        emit('message_time', dt_string.split()[0],
             room=Find_specific_user(session["user"]).get_session_id())
        emit("message4", url_for('static', filename='images/' + str(id) + "." + type_of_file),
             room=Find_specific_user(session["user"]).get_session_id())

        if id == 0:
            id = "L"

        whole_msg = ""
        print("the current user is:" + str(session["user"]))
        print("the list of twins is:")
        print("the other user before change is" + str(other_user))
        # check if other user is connected to this specific chat
        if len(Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_session_id()) > 0:
            print(Find_name(int(Find_specific_user(session["user"]).get_name_other_user())))
            print(dict_of_msg[Find_name(int(Find_specific_user(session["user"]).get_name_other_user()))].split("~")[1])
            print(type(
                dict_of_msg[Find_name(int(Find_specific_user(session["user"]).get_name_other_user()))].split("~")[1]))
            print(type(session["user"]))
            # chceck if the other user connect to chat-rooom with your user
            if Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_name_other_user() == session["user"]:
                today = datetime.now()
                dt_string = today.strftime("%d/%m/%Y %H:%M:%S")
                # send the image to other user
                emit('message_time', dt_string.split()[0],
                     room=Find_specific_user(
                         Find_specific_user(session["user"]).get_name_other_user()).get_session_id())
                emit('message5', url_for('static', filename='images/' + str(id) + "." + type_of_file),
                     room=Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_session_id())
        sql2 = ""
        if id == "L":
            today = datetime.now()
            dt_string = today.strftime("%d/%m/%Y %H:%M:%S")
            sql2 = ''' INSERT INTO chat VALUES(''' + str(0) + "," + '"' + str(session["user"]) + '"' + "," + '"' + str(
                Find_specific_user(session["user"]).get_name_other_user()) + '"' + "," + '"' + "" + '"' + ","+'"'+(dt_string)+'"'+ ")"
            found_first_time = True
        else:
            today = datetime.now()
            dt_string = today.strftime("%d/%m/%Y %H:%M:%S")
            sql2 = ''' INSERT INTO chat VALUES(''' + str(id) + "," + '"' + str(
                session["user"]) + '"' + "," + '"' + str(
                Find_specific_user(session["user"]).get_name_other_user()) + '"' + "," + '"' + "" + '"' + ","+'"'+(dt_string)+'"'+ ")"
            found_first_time = True
        # insert the message to message database
        print(sql2)
        cur = conn.cursor()
        cur.execute(sql2)
        conn.commit()
    except Exception as e:
        print(e)

# search the current id on sql table chats
def search_id():
    conn = sqlite3.connect('chats_21.sqlite3')
    print("Opened database successfully")

    try:
        cursor2 = conn.execute("CREATE TABLE chat(id INTEGER, name_from TEXT,  name_to TEXT, info TEXT, time TEXT)")
    except:
        pass
    cursor = conn.execute("SELECT id, name_from,name_to,info,time from chat")

    id = "L"
    for row in cursor:
        id = row[0]
    return id


# the main function that listen to client request about get chat history, and send text messages
@app.route("/chats", methods=["POST", "GET"])
@socketio.on('User has connected!')
def display_history(msg):
    #global vars
    global index_Sending
    global zz
    global other_user
    global users_couple
    global decryption
    global jj
    global found_first_time
    global color_choice
    global font
    global size
    # end global vars
    print("now the server will display history chat")
    try:
        conn = sqlite3.connect('chats_21.sqlite3')
        try:
            cursor2 = conn.execute(
                "CREATE TABLE chat( id INTEGER, name_from TEXT,  name_to TEXT, info TEXT, time TEXT)")
        except Exception as e:
            print(e)
        id = search_id()
        cursor = conn.execute("SELECT id,name_from,name_to,info,time from chat")
        print("the request sid is: " + request.sid)
        Find_specific_user(session["user"]).set_session_id(request.sid)
        dict_of_msg[Find_name(session["user"])] = request.sid + "~" + str(
            int(Find_specific_user(session["user"]).get_name_other_user()))

        emit("size", size, room=Find_specific_user(session["user"]).get_session_id())
        emit('font', font, room=Find_specific_user(session["user"]).get_session_id())

        emit('color', color_choice, room=Find_specific_user(session["user"]).get_session_id())
        emit('message', "you connected!!!", room=Find_specific_user(session["user"]).get_session_id())
        emit('messagenew', "your username is:" + Find_name(session["user"]),
             room=Find_specific_user(session["user"]).get_session_id())
        emit('messagenew', "you talk with:" + Find_name(other_user),
             room=Find_specific_user(session["user"]).get_session_id())

        print(session["user"])
        print(other_user)
        print("--------------------------------")
        # export history of chat in this for loop
        for row in cursor:
            dict_of_msg[Find_name(session["user"])] = request.sid + "~" + str(
                int(Find_specific_user(session["user"]).get_name_other_user()))
            if (int(row[2]) == other_user and int(row[1]) == session["user"]):
                if row[3] == "":
                    list_of_files = glob.glob(os.getcwd() + "\static\\images\\*.*")
                    serial_file = 0
                    for serial in range(len(list_of_files)):
                        if str(row[0]) == \
                                list_of_files[serial].split("\\")[len(list_of_files[serial].split("\\")) - 1].split(
                                    ".")[0]:
                            serial_file = serial
                            break
                    print(list_of_files[serial_file])
                    zz = zz + 1

                    print(list_of_files[serial_file].split("\\")[
                              len(list_of_files[serial_file].split("\\")) - 1].split(".")[1])
                    emit('message_hour', row[4].split()[1], room=Find_specific_user(session["user"]).get_session_id())
                    emit('message_time', row[4].split()[0],
                         room=Find_specific_user(session["user"]).get_session_id())
                    emit('message4', url_for('static', filename='images/' + str(row[0]) + "." +
                                                                list_of_files[serial_file].split("\\")[len(
                                                                    list_of_files[serial_file].split(
                                                                        "\\")) - 1].split(".")[1]),
                         room=Find_specific_user(session["user"]).get_session_id())
                else:

                    print("here you sed the history of chat")
                    emit('message_hour', row[4].split()[1], room=Find_specific_user(session["user"]).get_session_id())

                    emit('message_time', row[4].split()[0],
                         room=Find_specific_user(session["user"]).get_session_id())
                    emit('message', Find_name(session["user"])+" : "+row[3], room=Find_specific_user(session["user"]).get_session_id())
            if (int(row[1]) == other_user and int(row[2]) == session["user"]):
                if row[3] == "":
                    list_of_files = glob.glob(os.getcwd() + "\static\\images\\*.*")
                    serial_file = 0
                    serial = 0
                    for serial in range(len(list_of_files)):
                        if str(row[0]) == \
                                list_of_files[serial].split("\\")[len(list_of_files[serial].split("\\")) - 1].split(
                                    ".")[0]:
                            serial_file = serial
                            break

                    emit('message_hour', row[4].split()[1], room=Find_specific_user(session["user"]).get_session_id())
                    emit('message_time', row[4].split()[0],
                         room=Find_specific_user(session["user"]).get_session_id())
                    emit('message5', url_for('static', filename='images/' + str(row[0]) + "." +
                                                                list_of_files[serial_file].split("\\")[len(
                                                                    list_of_files[serial_file].split(
                                                                        "\\")) - 1].split(".")[1]),
                         room=Find_specific_user(session["user"]).get_session_id())
                else:

                    emit('message_hour', row[4].split()[1], room=Find_specific_user(session["user"]).get_session_id())
                    emit('message_time', row[4].split()[0],
                         room=Find_specific_user(session["user"]).get_session_id())
                    emit('message2', Find_name(other_user)+" : "+row[3], room=Find_specific_user(session["user"]).get_session_id())
        emit('messagenew', "this is a new messages from here ! ",
             room=Find_specific_user(session["user"]).get_session_id())

    except Exception as e:
        print(e)
        display_error()

# display error screen
@app.route("/error")
def display_error():
    try:
        return render_template("error_screen.html", file_name="3")
    except Exception as e:
        print(e)

# the main function that listen to client request about get chat history, and send text messages
@app.route("/chats", methods=["POST", "GET"])
@socketio.on('message')
def handleMessage2(msg):
    #global vars
    global index_Sending
    global zz
    global other_user
    global users_couple
    global decryption
    global jj
    global found_first_time
    global color_choice
    global font
    global size
    # end of global vars
    try:
        print("the session of user is: ",session["user"])
        print(request.form["formFile"])
    except:
        print("printfff")
    sql2 = ""
    today = datetime.now()
    dt_string = today.strftime("%d/%m/%Y %H:%M:%S")
    try:
        print("you are in the right function!!!!!!")
        conn = sqlite3.connect('chats_21.sqlite3')
        try:
            cursor2 = conn.execute("CREATE TABLE chat( id INTEGER, name_from TEXT,  name_to TEXT, info TEXT, time TEXT)")
        except Exception as e:
            print(e)
        id = search_id()
        cursor = conn.execute("SELECT id,name_from,name_to,info,time from chat")
        print("the request sid is: "+request.sid)
        Find_specific_user(session["user"]).set_session_id(request.sid)
        dict_of_msg[Find_name(session["user"])] = request.sid + "~" + str(
            int(Find_specific_user(session["user"]).get_name_other_user()))


        whole_msg = Find_name(session["user"]) + ": " + msg + " " + dt_string
        print(msg.encode())
        if jj == 1:
            jj = 1
        # send the message to current client
        emit('message_time', dt_string.split()[0],
             room=Find_specific_user(session["user"]).get_session_id())
        emit('message_hour', dt_string.split()[1], room=Find_specific_user(session["user"]).get_session_id())

        emit('message', whole_msg, room=Find_specific_user(session["user"]).get_session_id())
        print("the current user is:" + str(session["user"]))
        print("the list of twins is:")
        print(users_couple.split("|"))
        print("the other user before change is" + str(other_user))
        # check if other user have session id- this indicate he connect
        if len(Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_session_id()) > 0:
            # check if his(other user) connection is to the current client
            if Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_name_other_user() == session["user"]:
                # send the text message to other user
                emit('message_time', dt_string.split()[0],
                     room=Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).get_session_id())

                emit('message_hour', dt_string.split()[1],
                     room=Find_specific_user(
                         Find_specific_user(session["user"]).get_name_other_user()).get_session_id())
                emit('message2', whole_msg, room=Find_specific_user(Find_specific_user(session["user"]).get_name_other_user()).
                     get_session_id())
            else:
                print("the other client in talk with other user")
        else:
            print("the other client isn't connected")
        sql2 = ""
        if id == "L":
            sql2 = ''' INSERT INTO chat VALUES(''' + str(0) + "," + '"' + str(
                session["user"]) + '"' + "," + '"' + str(
                Find_specific_user(session["user"]).get_name_other_user()) + '"' + "," + '"' + (
                               msg + dt_string) + '"' +','+ '"'+(dt_string)+'"'+ ")"
            found_first_time = True
        else:
            id = id + 1
            sql2 = ''' INSERT INTO chat VALUES(''' + str(id) + "," + '"' + str(
                session["user"]) + '"' + "," + '"' + str(
                Find_specific_user(session["user"]).get_name_other_user()) + '"' + "," + '"' + (
                           msg + dt_string) + '"' +','+ '"'+(dt_string)+'"'+ ")"
            found_first_time = True

        # insert the text message to database
        print(sql2)
        LOCK_flask.acquire()
        cur = conn.cursor()
        cur.execute(sql2)
        conn.commit()
        LOCK_flask.release()
        print("write succesfully")

        # emit('message',session["user"]+": "+msg+" "+dt_string)

    except Exception as e:
        print("he wronggggggggggggggggg")
        print(e)
        return render_template("error_screen.html", file_name="3")


# display user page
@app.route("/user", methods=["POST", "GET"])
def user():
    email = None

    if "user" in session:
        user = session["user"]
        if request.method == "POST":
            email = request.form["email"]
            session["email"] = email
            found_user = users.query.filter_by(name=user).first()
            found_user.email = email
            db.session.commit()
            flash("email was saved")
        else:
            if "email" in session:
                email = session["email"]
        return render_template("user.html", email=email)
    else:
        flash("you are not logged in")
        return redirect(url_for("login"))


# logout that redirect to login page
@app.route("/logout")
def logout():
    if "is_connect" in session:
        session.pop("is_connect",None)
    if "user" in session:
        user = session["user"]
        flash(f"you have been logged out {user}", "info")
    try:
        list_online_users.remove(Find_name(session["user"]))
    except:
        print("no session here!!!!!!!!!!!!!!!!!!")
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))


# the main function- like main loop
def main():
    # the main loop
    db.create_all()  # create and open database
    define_history()
    print(dict_of_msg)
    define_user_to_user()
    for i in range(len(list_user_to_user)):
        print(i)
        print(list_user_to_user[i])
    print(Find_specific_user(1))
    print(list_user_to_user)
    print("run the app")
    app.thread = True
    socketio.run(app, host="0.0.0.0")  # run the socketio and wait for client request

if __name__ == "__main__":
    main()
