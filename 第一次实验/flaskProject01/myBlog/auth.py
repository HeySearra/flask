import functools

from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from myBlog.db import get_db

# 实例化蓝图
bp = Blueprint("auth", __name__, url_prefix="/auth")


def login_required(view):
    """装饰器，验证用户是否登录
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


@bp.before_app_request
def load_logged_in_user():
    """在每次request视图开始前执行
    查询用户是否登录，若登录，则记录用户信息在g里
    """
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.route("/register", methods=("GET", "POST"))
def register():
    """注册
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # 建立数据库连接
        db = get_db()
        error = None

        # 检查用户名和密码是否为空
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        # 检查是否已注册
        elif (
            db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
            is not None
        ):
            error = f"User {username} is already registered."

        # 是合法的注册
        if error is None:
            # 将数据插入数据库表
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            # 提交事务
            db.commit()
            # 重定向到注册页
            return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """登录
    把登录的信息加到session里
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # 建立数据库连接
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            error = "Incorrect username."
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password."

        if error is None:
            # 刷新session，存储uid
            session.clear()
            session["user_id"] = user["id"]
            # 重定向到index页
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/login.html")


@bp.route("/logout")
def logout():
    """注销
    清除登录时保存的session
    """
    session.clear()
    # 重定向到index页
    return redirect(url_for("index"))
