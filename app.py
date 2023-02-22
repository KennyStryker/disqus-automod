import datetime
import json
import re
import os
from urllib.parse import urlparse
from pathlib import Path

import bcrypt
import requests
import validators
import yaml
from discord_webhook import DiscordEmbed, DiscordWebhook
from flask import *
from flask_mysqldb import MySQL, MySQLdb

current_directory = Path(__file__).parent.resolve()

allowed_domains = {
    'mangafire-3': {
        'name': 'MangaFire',
        'warning_log': 9577938413
    },
    '9anime-to': {
        'name': '9Anime',
        'warning_log': 6292105195
    }
}

db = yaml.load(open(os.path.join(current_directory, "db.yaml")), Loader=yaml.FullLoader)

API_KEY = db["API_KEY"]
access_token = db["access_token"]

app = Flask(__name__)

app.config["MYSQL_HOST"] = db["HOST"]
app.config["MYSQL_USER"] = db["USER"]
app.config["MYSQL_PASSWORD"] = db["PASSWORD"]
app.config["MYSQL_DB"] = db["DB"]
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

app.secret_key = "RfBQHtGTWu"

mysql = MySQL(app)


class DiscordAlert:

    global API_KEY
    global access_token

    def __init__(self, comment_id, reason, timeout=0, delete_comments=0):

        url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
            API_KEY, comment_id, access_token
        )

        response = requests.get(url)
        response = json.loads(response.text)

        if response["response"]["forum"] not in allowed_domains:
            raise Exception
        
        self.user = response["response"]["author"]["username"]
        self.comment_id = int(comment_id)
        self.platform = response["response"]["forum"]
        self.reason = reason
        self.timeout_days = int(timeout)
        self.delete_comments = delete_comments

        cleanr = re.compile("<.p*?>")
        message = re.sub(
            cleanr,
            "<br>",
            response["response"]["message"]
            .replace("&amp;", "and")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
        )

        message = message.replace(";", "")

        self.message = message
        self.editabletime = response["response"]["editableUntil"]
        self.mod = session.get("name")
        print(self.mod)
        self.comment_url = (
            "https://{}.disqus.com/admin/moderate/all/search/id:{}".format(
                self.platform, comment_id
            )
        )

    def send_alert_timeout(self):

        webhook = DiscordWebhook(url=db["WEBHOOK"])

        embed = DiscordEmbed(title="Timeout Issued", color=0x5A2E98)

        embed.set_author(name="View Comment", url=self.comment_url)

        embed.add_embed_field(name="User", value=self.user)
        embed.add_embed_field(name="Comment ID", value=self.comment_id)
        embed.add_embed_field(name="Platform", value=allowed_domains[self.platform]['name'])
        embed.add_embed_field(
            name="Timeout Duration", value="{} Days".format(self.timeout_days)
        )
        embed.add_embed_field(name="Reason", value=self.reason)
        embed.add_embed_field(name="Moderator", value=self.mod)

        webhook.add_embed(embed)
        response = webhook.execute()

        print("{} = Timeout Alert Sent".format(session.get("name")))

    def send_alert_ban(self):

        webhook = DiscordWebhook(url=db["WEBHOOK"])
        embed = DiscordEmbed(title="Permanent Ban Issued", color=0x5A2E98)

        embed.set_author(name="View Comment", url=self.comment_url)

        embed.add_embed_field(name="User", value=self.user)
        embed.add_embed_field(name="Comment ID", value=self.comment_id)
        embed.add_embed_field(name="Platform", value=allowed_domains[self.platform]['name'])
        embed.add_embed_field(name="Reason", value=self.reason)
        embed.add_embed_field(name="Moderator", value=self.mod)

        webhook.add_embed(embed)
        response = webhook.execute()

        print("{} = Ban Alert Sent".format(session.get("name")))

    def timeout(self):

        isEditable = (
            datetime.datetime.strptime(self.editabletime, "%Y-%m-%dT%H:%M:%S")
            > datetime.datetime.now()
        )

        url_delete_comment = "https://disqus.com/api/3.0/posts/remove.json?api_key={}&post={}&access_token={}".format(
            API_KEY, self.comment_id, access_token
        )

        ban_reason = self.reason + " - " + self.mod

        timeout_duration = (
            datetime.datetime.now() + datetime.timedelta(days=self.timeout_days)
        ).strftime("%Y-%m-%d %H:%M:%S")

        print(isEditable)

        if isEditable:

            timeout_message = """<a><b>This comment has been deleted for violating <a href="https://docs.google.com/document/d/1GbXfUz_2iUeejtMjL48_vaW7011uIFnU1Q_wO0oieuA/edit"><b><u>9Anime Comment Policy</u></b></a>.<br><br>You have been given a timeout ban for {} Day(s). If you're given another timeout ban within the next 30 days, you will be banned.<br>Warned by: {}<br>Reason: {}<br><br>Think you've been wrongly warned? <a href="https://discord.gg/9anime"><b>Post an appeal!</b></a><br>--------------------------------------------------</b><br>""".format(
                self.timeout_days, self.mod, self.reason
            )

            url_vote = "https://disqus.com/api/3.0/posts/vote.json?api_key={}&post={}&access_token={}&vote=1".format(
                API_KEY, self.comment_id, access_token
            )

            url_editcomment = "https://disqus.com/api/3.0/posts/update.json?api_key={}&post={}&access_token={}&message={}".format(
                API_KEY, self.comment_id, access_token, timeout_message + self.message
            )
            self.edited = requests.post(url_editcomment)
            self.upvoted = requests.post(url_vote)

            print("Edited = {}".format(self.edited))
            print("Upvoted = {}".format(self.upvoted))

        else:
            timeout_message = """Your comment has been deleted for violating <a href="https://docs.google.com/document/d/1GbXfUz_2iUeejtMjL48_vaW7011uIFnU1Q_wO0oieuA/edit"><b><u>9Anime Comment Policy</u></b></a>.<br><br>You have been given a timeout ban for {} Day(s). If you're given another timeout ban within the next 30 days, you will be banned.<br><br>Username: @{}:disqus<br>Warned By: {}<br>Reason: {}<br>Your Comment: <spoiler>{}</spoiler>""".format(
                self.timeout_days, self.user, self.mod, self.reason, self.message
            )

            url_post = "https://disqus.com/api/3.0/posts/create.json?api_key={}&thread={}&access_token={}&message={}".format(
                API_KEY, allowed_domains[self.platform]['warning_log'], access_token, timeout_message
            )
            self.posted = requests.post(url_post)

            print("Posted = {}".format(self.posted))

        if self.delete_comments:
            url_ban_user = "https://disqus.com/api/3.0/forums/block/banPostAuthor.json?api_key={}&post={}&access_token={}&dateExpires={}&notes={}&banEmail=1&banUser=1&retroactiveAction=1".format(
                API_KEY, self.comment_id, access_token, timeout_duration, ban_reason
            )
        else:
            url_ban_user = "https://disqus.com/api/3.0/forums/block/banPostAuthor.json?api_key={}&post={}&access_token={}&dateExpires={}&notes={}&banEmail=1&banUser=1".format(
                API_KEY, self.comment_id, access_token, timeout_duration, ban_reason
            )

        self.deleted = requests.post(url_delete_comment)
        self.banned = requests.post(url_ban_user)

        print("Deleted = {}".format(self.deleted))
        print("Banned = {}".format(self.banned))

        self.send_alert_timeout()

    def ban(self):

        isEditable = (
            datetime.datetime.strptime(self.editabletime, "%Y-%m-%dT%H:%M:%S")
            > datetime.datetime.now()
        )

        url_delete_comment = "https://disqus.com/api/3.0/posts/remove.json?api_key={}&post={}&access_token={}".format(
            API_KEY, self.comment_id, access_token
        )

        ban_reason = self.reason + " - " + self.mod

        print(isEditable)

        if isEditable:

            ban_message = """<a><b>This comment has been deleted for violating <a href="https://docs.google.com/document/d/1GbXfUz_2iUeejtMjL48_vaW7011uIFnU1Q_wO0oieuA/edit"><b><u>9Anime Comment Policy</u></b></a><br><br>You have been permanently banned.<br>Banned by: {}<br>Reason: {}<br><br>Think you've been wrongly banned? <a href="https://discord.gg/9anime"><b>Post an appeal</b></a><br>---------------------------------------------------</b><br>""".format(
                self.mod, self.reason
            )

            url_vote = "https://disqus.com/api/3.0/posts/vote.json?api_key={}&post={}&access_token={}&vote=1".format(
                API_KEY, self.comment_id, access_token
            )

            url_editcomment = "https://disqus.com/api/3.0/posts/update.json?api_key={}&post={}&access_token={}&message={}".format(
                API_KEY, self.comment_id, access_token, ban_message + self.message
            )
            self.edited = requests.post(url_editcomment)
            self.upvoted = requests.post(url_vote)

            print("Edited = {}".format(self.edited))
            print("Upvoted = {}".format(self.upvoted))

        else:
            ban_message = """This comment has been deleted for violating <a href="https://docs.google.com/document/d/1GbXfUz_2iUeejtMjL48_vaW7011uIFnU1Q_wO0oieuA/edit"><b><u>9Anime Comment Policy</u></b></a><br><br>You have been banned.<br><br>Username: @{}:disqus<br>Reason: {}<br>Banned By: {}<br>Your Comment: <spoiler>{}</spoiler>""".format(
                self.user, self.reason, self.mod, self.message
            )

            url_post = "https://disqus.com/api/3.0/posts/create.json?api_key={}&thread={}&access_token={}&message={}".format(
                API_KEY, allowed_domains[self.platform]['warning_log'], access_token, ban_message
            )
            self.posted = requests.post(url_post)

            print("Posted = {}".format(self.posted))

        if self.delete_comments:
            url_ban_user = "https://disqus.com/api/3.0/forums/block/banPostAuthor.json?api_key={}&post={}&access_token={}&notes={}&banEmail=1&banUser=1&retroactiveAction=1".format(
                API_KEY, self.comment_id, access_token, ban_reason
            )
        else:
            url_ban_user = "https://disqus.com/api/3.0/forums/block/banPostAuthor.json?api_key={}&post={}&access_token={}&notes={}&banEmail=1&banUser=1".format(
                API_KEY, self.comment_id, access_token, ban_reason
            )

        self.deleted = requests.post(url_delete_comment)
        self.banned = requests.post(url_ban_user)

        print("Deleted = {}".format(self.deleted))
        print("Banned = {}".format(self.banned))

        self.send_alert_ban()


@app.route("/", methods=["POST", "GET"])
def login():

    if session.get("name"):
        return redirect(url_for("choice"))
    else:
        error = None
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"].encode("utf-8")

            try:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute("SELECT * FROM mods WHERE username=%s", (username,))
                user = curl.fetchone()
                curl.close()

                if user:
                    if bcrypt.hashpw(
                        password, user["password"].encode("utf-8")
                    ) == user["password"].encode("utf-8"):
                        session["name"] = user["username"]
                        session['bg_image'] = get_background_image()
                        return redirect(url_for("choice"))
                    else:
                        flash("Invalid credentials")
                        return redirect(url_for("login"))
                else:
                    flash("Invalid credentials")
                    return redirect(url_for("login"))
            except Exception as e:
                flash("An error occurred.")
                print(e)
                return redirect(url_for("login"))

        return render_template("login.html")


def get_background_image():

    files = os.listdir(os.path.join(current_directory, 'static', 'custom_background'))

    for file in files:
        if session['name'] == file.split('.')[0]:
            return file
    return False


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if session.get("name"):
        session.pop("name", None)
        return redirect(url_for("login"))
    else:
        flash("You need to login to log out.")
        return redirect(url_for("login"))


@app.route("/changepassword/", methods=["POST", "GET"])
def changepassword():
    error = None
    if session.get("name"):

        if request.method == "POST":
            current_password = request.form["current_password"].encode("utf-8")

            try:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute(
                    "SELECT * FROM mods WHERE username=%s", (session.get("name"),)
                )
                user = curl.fetchone()
                curl.close()

                if user:
                    if bcrypt.hashpw(
                        current_password, user["password"].encode("utf-8")
                    ) == user["password"].encode("utf-8"):
                        new_password = request.form["new_password"].encode("utf-8")
                        confirm_password = request.form["confirm_password"].encode(
                            "utf-8"
                        )

                        if new_password == confirm_password:
                            hash_password = bcrypt.hashpw(
                                new_password, bcrypt.gensalt()
                            )

                            cur = mysql.connection.cursor()
                            cur.execute(
                                "UPDATE mods SET password = %s WHERE username = %s",
                                (
                                    hash_password,
                                    session.get("name"),
                                ),
                            )
                            mysql.connection.commit()

                            flash("Password changed", "success")
                            return redirect(url_for("changepassword"))
                        else:
                            flash("New and confirm password must be same.", "danger")
                        return redirect(url_for("changepassword"))
                    else:
                        flash("Incorrect Password", "danger")
                        return redirect(url_for("changepassword"))
                else:
                    flash("An error occurred.", "danger")
                    return redirect(url_for("changepassword"))
            except Exception as e:
                print(e)
                flash("An error occurred.", "danger")
                return redirect(url_for("changepassword"))

        return render_template("changepassword.html")
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))

@app.route("/changebackground/", methods=["POST", "GET"])
def changebackground():
    error = None
    if session.get("name"):

        if request.method == "POST":

            if request.form['action'] == 'Remove Background':
                os.remove(os.path.join(current_directory, 'static', 'custom_background', session['bg_image']))
                session.pop('bg_image', None)
                flash("Background removed", "success")
                return redirect(url_for("changebackground"))

            if request.form['action'] == 'Change Background':
                bg_image = request.files['bg_image']

                if bg_image.filename == '':
                    flash("File can not be empty", "danger")
                    return redirect(url_for("changebackground"))

                bg_image_ext = '.' + bg_image.filename.split('.')[-1]

                if bg_image_ext not in ['.jpg', '.jpeg', '.png']:
                    flash("File is not an image", "danger")
                    return redirect(url_for("changebackground"))

                if session.get('bg_image'):
                    os.remove(os.path.join(current_directory, 'static', 'custom_background', session['bg_image']))
                    session.pop('bg_image', None)

                bg_image_filename = session.get("name") + bg_image_ext

                bg_image.filename = bg_image_filename

                bg_image.save('{}/static/custom_background/{}'.format(current_directory, bg_image.filename))

                session['bg_image'] = bg_image.filename

                flash("Background changed", "success")
                return redirect(url_for("changebackground"))

        return render_template("changebackground.html")
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/registermods", methods=["POST", "GET"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        name = request.form["name"]
        password = request.form["password"].encode("utf-8")
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO mods (username, password) VALUES (%s,%s)",
            (
                name,
                hash_password,
            ),
        )
        mysql.connection.commit()
        session["name"] = request.form["name"]
        return redirect(url_for("login"))


@app.route("/choice", methods=["POST", "GET"])
def choice():
    if session.get("name"):
        if request.method == "POST":
            if request.form["choice"] == "Check User":
                return redirect(url_for("viewuser"))
            elif request.form["choice"] == "Check Comment":
                return redirect(url_for("viewcomment"))
        return render_template("choice.html")
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/viewcomment/", methods=["POST", "GET"])
def viewcomment():
    if session.get("name"):
        error = None
        if request.method == "POST":
            try:
                comment = request.form["comment_id"]

                if comment.isdigit():
                    comment_id = int(comment)
                elif validators.url(comment):
                    comment_url = urlparse(comment)
                    if not comment_url.fragment:
                        if comment_url.netloc == "disq.us":
                            comment_url = comment
                            comment_url = requests.head(comment_url).headers["Location"]
                            comment_id = int(comment_url.split("-")[-1])
                        elif (
                            comment_url.netloc == "disqus.com"
                            or comment_url.netloc == "9anime-to.disqus.com"
                            or comment_url.netloc == "mangafire-3.disqus.com"
                        ):
                            comment_id = int(comment_url.path.split(":")[1])
                        else:
                            flash("Invalid Comment URL")
                            return redirect(url_for("viewcomment"))
                    elif comment_url.fragment:
                        comment_id = int(comment_url.fragment.split("-")[1])
                    else:
                        flash("Invalid Comment URL")
                        return redirect(url_for("viewcomment"))
                else:
                    flash("Invalid Comment ID")
                    return redirect(url_for("viewcomment"))

                url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
                    API_KEY, comment_id, access_token
                )

                response = requests.get(url)
                response = json.loads(response.text)

                if response["response"]["forum"] not in allowed_domains:
                    raise Exception

                return redirect(url_for("checkcomment", comment_id=comment_id))
            except Exception as e:
                print(e)
                flash("Invalid Comment ID")
                return redirect(url_for("viewcomment"))

        return render_template("viewcomment.html")
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/checkcomment/<int:comment_id>/", methods=["POST", "GET"])
def checkcomment(comment_id):
    if session.get("name"):
        try:

            if "timeout_btn" in request.form:

                url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
                    API_KEY, comment_id, access_token
                )

                response = requests.get(url)
                response = json.loads(response.text)

                user_data = {
                    "display_name": response["response"]["author"]["name"],
                    "username": response["response"]["author"]["username"],
                    "content": response["response"]["message"]
                    .replace("&amp;", "&")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">"),
                    "upvotes": response["response"]["likes"],
                    "downvotes": response["response"]["dislikes"],
                }

                print(user_data)

                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                # curl.execute("SELECT count(*) FROM information_schema.TABLES WHERE (TABLE_SCHEMA = '{}') AND (TABLE_NAME = '{}')".format(app.config['MYSQL_DB'], user_data['username']))
                curl.execute("SHOW TABLES LIKE '{}'".format(user_data["username"]))
                user = curl.fetchone()
                curl.close()

                # try:
                #    user = user['count(*)']
                # except:
                #    discord_alert = DiscordAlert(comment_id, reason=request.form['timeout_reason'], timeout=request.form['timeout_duration'])
                #    discord_alert.timeout()

                #    success = "Timeout Issued"
                #    return render_template("comment.html", comment_id = comment_id, user_data = user_data, success=success)

                if user:
                    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    curl.execute(
                        "INSERT INTO {}(moderator, reason, permaban) VALUES ('{}', '{}', 0)".format(
                            user_data["username"],
                            session.get("name"),
                            request.form["timeout_reason"],
                        )
                    )
                    mysql.connection.commit()
                    curl.close()
                else:
                    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    curl.execute(
                        "create table {}(id INT NOT NULL AUTO_INCREMENT, moderator VARCHAR(50) NOT NULL, reason VARCHAR(255) NOT NULL, permaban INT NOT NULL, log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (id))".format(
                            user_data["username"]
                        )
                    )
                    curl.execute(
                        "INSERT INTO {}(moderator, reason, permaban) VALUES ('{}', '{}', 0)".format(
                            user_data["username"],
                            session.get("name"),
                            request.form["timeout_reason"],
                        )
                    )
                    mysql.connection.commit()
                    curl.close()

                if request.form.get("timeout_delete_comments"):
                    discord_alert = DiscordAlert(
                        comment_id,
                        reason=request.form["timeout_reason"],
                        timeout=request.form["timeout_duration"],
                        delete_comments=1,
                    )
                else:
                    discord_alert = DiscordAlert(
                        comment_id,
                        reason=request.form["timeout_reason"],
                        timeout=request.form["timeout_duration"],
                    )
                discord_alert.timeout()

                flash("Timeout Issued")
                return redirect(url_for("checkcomment", comment_id=comment_id))

            if "ban_btn" in request.form:
                url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
                    API_KEY, comment_id, access_token
                )

                response = requests.get(url)
                response = json.loads(response.text)

                user_data = {
                    "display_name": response["response"]["author"]["name"],
                    "username": response["response"]["author"]["username"],
                    "content": response["response"]["message"]
                    .replace("&amp;", "&")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">"),
                    "upvotes": response["response"]["likes"],
                    "downvotes": response["response"]["dislikes"],
                }

                print(user_data)

                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                # curl.execute("SELECT count(*) FROM information_schema.TABLES WHERE (TABLE_SCHEMA = '{}') AND (TABLE_NAME = '{}')".format(app.config['MYSQL_DB'], user_data['username']))
                curl.execute("SHOW TABLES LIKE '{}'".format(user_data["username"]))
                user = curl.fetchone()
                curl.close()

                # try:
                #    user = user['count(*)']
                # except:
                #    discord_alert = DiscordAlert(comment_id, reason=request.form['ban_reason'])
                #    discord_alert.ban()

                #    success = "Permanent Ban Issued"
                #    return render_template("comment.html", comment_id = comment_id, user_data = user_data, success=success)

                if user:
                    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    curl.execute(
                        "INSERT INTO {}(moderator, reason, permaban) VALUES ('{}', '{}', 1)".format(
                            user_data["username"],
                            session.get("name"),
                            request.form["ban_reason"],
                        )
                    )
                    mysql.connection.commit()
                    curl.close()
                else:
                    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    curl.execute(
                        "CREATE TABLE {}(id INT NOT NULL AUTO_INCREMENT, moderator VARCHAR(50) NOT NULL, reason VARCHAR(255) NOT NULL, permaban INT NOT NULL, log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (id))".format(
                            user_data["username"]
                        )
                    )
                    curl.execute(
                        "INSERT INTO {}(moderator, reason, permaban) VALUES ('{}', '{}', 1)".format(
                            user_data["username"],
                            session.get("name"),
                            request.form["ban_reason"],
                        )
                    )
                    mysql.connection.commit()
                    curl.close()

                if request.form.get("ban_delete_comments"):
                    discord_alert = DiscordAlert(
                        comment_id, reason=request.form["ban_reason"], delete_comments=1
                    )
                else:
                    discord_alert = DiscordAlert(
                        comment_id, reason=request.form["ban_reason"]
                    )
                discord_alert.ban()

                flash("Permanent Ban Issued")
                return redirect(url_for("checkcomment", comment_id=comment_id))

            try:

                if request.method == "POST":
                    comment = request.form["comment_id"]

                    if comment.isdigit():
                        comment_id = int(comment)
                    elif validators.url(comment):
                        comment_url = urlparse(comment)
                        if not comment_url.fragment:
                            if comment_url.netloc == "disq.us":
                                comment_url = comment
                                comment_url = requests.head(comment_url).headers[
                                    "Location"
                                ]
                                comment_id = int(comment_url.split("-")[-1])
                            elif (
                                comment_url.netloc == "disqus.com"
                                or comment_url.netloc == "9anime-to.disqus.com"
                                or comment_url.netloc == "mangafire-3.disqus.com"
                            ):
                                comment_id = int(comment_url.path.split(":")[1])
                            else:
                                flash("Invalid Comment URL")
                                return redirect(url_for("viewcomment"))
                        elif comment_url.fragment:
                            comment_id = int(comment_url.fragment.split("-")[1])
                        else:
                            flash("Invalid Comment URL")
                            return redirect(url_for("viewcomment"))
                    else:
                        flash("Invalid Comment ID")
                        return redirect(url_for("viewcomment"))

                    url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
                        API_KEY, comment_id, access_token
                    )

                    response = requests.get(url)
                    response = json.loads(response.text)

                    if response["response"]["forum"] not in allowed_domains:
                        raise Exception

                    return redirect(url_for("checkcomment", comment_id=comment_id))

            except Exception as e:
                print(e)
                flash("Invalid Comment URL")
                return redirect(url_for("viewcomment"))

            comment_id = int(comment_id)

            url = "https://disqus.com/api/3.0/posts/details.json?api_key={}&post={}&access_token={}".format(
                API_KEY, comment_id, access_token
            )

            response = requests.get(url)
            response = json.loads(response.text)

            if response["response"]["forum"] not in allowed_domains:
                return redirect(url_for("not_found"))

            user_data = {
                "display_name": response["response"]["author"]["name"],
                "username": response["response"]["author"]["username"],
                "content": response["response"]["message"]
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">"),
                "upvotes": response["response"]["likes"],
                "downvotes": response["response"]["dislikes"],
            }

            print(user_data)

            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            # curl.execute("SELECT count(*) FROM information_schema.TABLES WHERE (TABLE_SCHEMA = '{}') AND (TABLE_NAME = '{}')".format(app.config['MYSQL_DB'], user_data['username']))
            curl.execute("SHOW TABLES LIKE '{}'".format(user_data["username"]))
            user = curl.fetchone()
            curl.close()

            print(user)

            # try:
            #    print("testing")
            #    user = user["count(*)"]
            # except:
            #    return render_template("comment.html", comment_id = comment_id, user_data = user_data)

            if user:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute(
                    "SELECT * from {} ORDER BY log_date DESC LIMIT 1".format(
                        user_data["username"]
                    )
                )
                user = curl.fetchone()
                curl.close()

                try:
                    wait_period = user["log_date"] + datetime.timedelta(days=30)
                except:
                    return render_template(
                        "comment.html", comment_id=comment_id, user_data=user_data
                    )

                user["log_date"] = user["log_date"].strftime("%B %d, %Y")

                print(user)

                if (wait_period >= datetime.datetime.now()) or (user["permaban"] == 1):
                    return render_template(
                        "comment.html",
                        comment_id=comment_id,
                        user_data=user_data,
                        ban_info=user,
                    )
                else:
                    return render_template(
                        "comment.html", comment_id=comment_id, user_data=user_data
                    )
            else:
                return render_template(
                    "comment.html", comment_id=comment_id, user_data=user_data
                )

        except Exception as e:
            print(e)
            return redirect(url_for("not_found"))
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/viewuser/", methods=["POST", "GET"])
def viewuser():
    if session.get("name"):
        error = None

        if request.method == "POST":
            try:
                username = request.form["username"]

                if validators.url(username):
                    username = urlparse(username)

                    if username.netloc == "disqus.com":
                        username = username.path.split("/")[2]
                    else:
                        flash("Invalid Profile Link")
                        return redirect(url_for("viewuser"))

                url = "https://disqus.com/api/3.0/users/details.json?api_key={}&user=username:{}&access_token={}".format(
                    API_KEY, username, access_token
                )

                response = requests.get(url)
                response = json.loads(response.text)

                if response["code"] != 0:
                    raise Exception

                username = response["response"]["username"]

                return redirect(url_for("checkuser", username=username))
            except Exception as e:
                print(e)
                flash("User doesn't exist")
                return redirect(url_for("viewuser"))

        return render_template("viewuser.html")
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/checkuser/<username>/", methods=["POST", "GET"])
def checkuser(username):
    if session.get("name"):
        error = None
        try:
            if request.method == "POST":
                try:
                    username = request.form["username"]

                    if validators.url(username):
                        username = urlparse(username)

                        if username.netloc == "disqus.com":
                            username = username.path.split("/")[2]
                        else:
                            flash("Invalid Profile Link")
                            return redirect(url_for("viewuser"))

                    url = "https://disqus.com/api/3.0/users/details.json?api_key={}&user=username:{}&access_token={}".format(
                        API_KEY, username, access_token
                    )

                    response = requests.get(url)
                    response = json.loads(response.text)

                    if response["code"] != 0:
                        raise Exception

                    username = response["response"]["username"]

                    return redirect(url_for("checkuser", username=username))
                except Exception as e:
                    print(e)
                    flash("User doesn't exist")
                    return redirect(url_for("viewuser"))

            url = "https://disqus.com/api/3.0/users/details.json?api_key={}&user=username:{}&access_token={}".format(
                API_KEY, username, access_token
            )

            response = requests.get(url)
            response = json.loads(response.text)

            if response["code"] != 0:
                raise Exception

            username = response["response"]["username"]

            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            # curl.execute("SELECT count(*) FROM information_schema.TABLES WHERE (TABLE_SCHEMA = '{}') AND (TABLE_NAME = '{}')".format(app.config['MYSQL_DB'], user_data['username']))
            curl.execute("SHOW TABLES LIKE '{}'".format(username))
            user = curl.fetchone()
            curl.close()

            if user:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute("SELECT * from {} ORDER BY log_date DESC".format(username))
                user = curl.fetchall()
                curl.close()

                for user_data in user:
                    user_data["log_date"] = user_data["log_date"].strftime("%B %d, %Y")

                return render_template("user.html", username=username, user_data=user)
            else:
                return render_template(
                    "user.html", username=username, no_moderation=True
                )

        except Exception as e:
            print(e)
            return redirect(url_for("not_found"))

    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/deleteuser/<username>/<int:id>/", methods=["POST", "GET"])
def deleteuser(username, id):
    if session.get("name"):
        try:
            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            curl.execute("SELECT * FROM {}".format(username))
            user = curl.fetchall()
            curl.close()

            if len(user) == 1:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute("DROP TABLE {}".format(username))
                mysql.connection.commit()
                curl.close()

                return redirect(url_for("checkuser", username=username))

            else:
                curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                curl.execute("DELETE FROM {} WHERE id={}".format(username, id))
                mysql.connection.commit()
                curl.close()

                return redirect(url_for("checkuser", username=username))
        except Exception as e:
            print(e)
            return redirect(url_for("not_found"))
    else:
        flash("Unauthorized Access.")
        return redirect(url_for("login"))


@app.route("/404")
def not_found():
    return render_template("404.html")


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")


if __name__ == '__main__':
    app.run()
