from flask import Flask, render_template, redirect, url_for, flash, session
import flask_mysqldb
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, NumberRange, Optional
import os
import datetime
from flask_bcrypt import Bcrypt

secret_key = os.urandom(24).hex()

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_key
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "inventory"

bcrypt = Bcrypt(app)

mysql = flask_mysqldb.MySQL(app)

class RegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    user_id = StringField("User ID", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class AddProductForm(FlaskForm):
    product_name = StringField("Product Name", validators=[DataRequired()])
    submit = SubmitField("Add Product")

class SearchForm(FlaskForm):
    search_by = StringField("Search by", validators=[DataRequired()])
    search_term = StringField("Search term", validators=[DataRequired()])
    submit = SubmitField("Search")

class AddToInventoryForm(FlaskForm):
    product_id = StringField("Product ID", validators=[DataRequired()])
    quantity_added = StringField("Quantity to add", validators=[DataRequired()])
    submit = SubmitField("Add to Inventory")

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Optional

class ViewProductLogsForm(FlaskForm):
    search_by = SelectField("Search by", choices=[
        ('', 'Select option'), 
        ('id', 'Product ID'), 
        ('month', 'Month'), 
        ('both', 'Both')
    ], validators=[DataRequired()])
    product_id = StringField("Product ID", validators=[Optional()])
    month = SelectField("Select month", choices=[
        ('', 'Select month'), 
        ('1', 'January'), ('2', 'February'), ('3', 'March'), ('4', 'April'),
        ('5', 'May'), ('6', 'June'), ('7', 'July'), ('8', 'August'),
        ('9', 'September'), ('10', 'October'), ('11', 'November'), ('12', 'December')
    ], validators=[Optional()])
    submit = SubmitField("View Logs")


class TransportForm(FlaskForm):
    product_id = IntegerField('Product ID', validators=[DataRequired(), NumberRange(min=1)])
    quantity_transported = IntegerField('Quantity to transport', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Transport')

class ViewTransportLogsForm(FlaskForm):
    search_by = SelectField("Search by", choices=[('', 'Select option'), ('id', 'Product ID'), ('month', 'Month'), ('both', 'Both')], validators=[DataRequired()])
    product_id = StringField("Product ID", validators=[Optional()])
    month = StringField("Select month", validators=[Optional()])
    submit = SubmitField("View Logs")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0] + 1
        user_id = str(datetime.date.today().year) + str(count).zfill(3)
        registration_date = datetime.date.today()
        registration_time = datetime.datetime.now().time()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        cur.execute("INSERT INTO users (id, email, first_name, last_name, password, registration_date, registration_time) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                    (user_id, form.email.data, form.first_name.data, form.last_name.data, hashed_password, registration_date, registration_time))
        mysql.connection.commit()
        # flash("Registration successful! You will be redirected to the home page in 3 seconds.")
        # return render_template("register_success.html")
        return redirect(url_for("index"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        print(form.user_id.data)
        print(form.password.data)
        cur.execute("SELECT password, first_name FROM users WHERE id = %s", (form.user_id.data,))
        result = cur.fetchone()
        if result:
            hashed_password = result[0]
            if bcrypt.check_password_hash(hashed_password, form.password.data):
                session['user_id'] = form.user_id.data
                session['first_name'] = result[1]  # Store first name in session
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid user ID or password")
        else:
            flash("Invalid user ID or password")
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('first_name', None)
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user_id=session['user_id'], first_name=session['first_name'])

@app.route("/profile")
def profile():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    cur = mysql.connection.cursor()
    cur.execute("SELECT email, first_name, last_name, registration_date FROM users WHERE id = %s", (session['user_id'],))
    result = cur.fetchone()
    if result:
        return render_template("profile.html", email=result[0], first_name=result[1], last_name=result[2], registration_date=result[3])
    else:
        flash("User not found")
        return redirect(url_for("dashboard"))
    
@app.route("/add_product", methods=["GET", "POST"])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    form = AddProductForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO products (name, quantity) VALUES (%s, %s)", 
                    (form.product_name.data, 0))
        mysql.connection.commit()
        cur.execute("SELECT id FROM products ORDER BY id DESC LIMIT 1")
        product_id = cur.fetchone()[0]
        flash("Product added successfully! Product ID is " + str(product_id))
    return render_template("add_product.html", form=form, user_id=session['user_id'], first_name=session['first_name'])

@app.route("/search_products", methods=["GET", "POST"])
def search_products():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    form = SearchForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        if form.search_by.data == "id":
            cur.execute("SELECT * FROM products WHERE id = %s", (form.search_term.data,))
        else:
            cur.execute("SELECT * FROM products WHERE name LIKE %s", ("%" + form.search_term.data + "%",))
        products = cur.fetchall()
        return render_template("search_products.html", form=form, products=products, user_id=session['user_id'], first_name=session['first_name'])
    return render_template("search_products.html", form=form, user_id=session['user_id'], first_name=session['first_name'])

@app.route("/log_inventory", methods=["GET", "POST"])
def log_inventory():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    form = AddToInventoryForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT quantity FROM products WHERE id = %s", (form.product_id.data,))
        result = cur.fetchone()
        if result:
            new_quantity = result[0] + int(form.quantity_added.data)
            cur.execute("UPDATE products SET quantity = %s WHERE id = %s", (new_quantity, form.product_id.data))
            mysql.connection.commit()
            cur.execute("INSERT INTO products_log (product_id, quantity_added, log_date, log_time, user_id) VALUES (%s, %s, %s, %s, %s)", 
                        (form.product_id.data, form.quantity_added.data, datetime.date.today(), datetime.datetime.now().time(), session['user_id']))
            mysql.connection.commit()
            flash("Inventory updated successfully!")
        else:
            flash("Product not found")
    return render_template("log_inventory.html", form=form, user_id=session['user_id'], first_name=session['first_name'])

@app.route("/view_product_logs", methods=["GET", "POST"])
def view_product_logs():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    
    form = ViewProductLogsForm()
    product_logs = None
    
    if form.validate_on_submit():
        search_by = form.search_by.data
        product_id = form.product_id.data
        month = form.month.data
        
        query = """SELECT pl.product_id, p.name, pl.quantity_added, pl.log_date, pl.log_time, 
                          CONCAT(u.first_name, ' ', u.last_name) AS full_name 
                   FROM products_log pl 
                   JOIN products p ON pl.product_id = p.id 
                   JOIN users u ON pl.user_id = u.id"""
        conditions = []
        params = []
        
        if search_by == 'id':
            conditions.append("pl.product_id = %s")
            params.append(product_id)
        elif search_by == 'month':
            conditions.append("MONTH(pl.log_date) = %s")
            params.append(month)
        elif search_by == 'both':
            conditions.append("pl.product_id = %s AND MONTH(pl.log_date) = %s")
            params.append(product_id)
            params.append(month)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        cur = mysql.connection.cursor()
        cur.execute(query, tuple(params))
        product_logs = cur.fetchall()
    
    return render_template("view_product_logs.html", form=form, product_logs=product_logs, user_id=session['user_id'], first_name=session['first_name'])

@app.route("/transport_products", methods=["GET", "POST"])
def transport_products():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    form = TransportForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT quantity FROM products WHERE id = %s", (form.product_id.data,))
        result = cur.fetchone()
        if result:
            current_quantity = result[0]
            if current_quantity >= form.quantity_transported.data:
                new_quantity = current_quantity - form.quantity_transported.data
                cur.execute("UPDATE products SET quantity = %s WHERE id = %s", (new_quantity, form.product_id.data))
                mysql.connection.commit()
                cur.execute("INSERT INTO transports_log (product_id, user_id, quantity_transported, log_date, log_time) VALUES (%s, %s, %s, %s, %s)", 
                            (form.product_id.data, session['user_id'], form.quantity_transported.data, datetime.date.today(), datetime.datetime.now().time()))
                mysql.connection.commit()
                flash("Product transported successfully!")
            else:
                flash("Not enough quantity in stock")
        else:
            flash("Product not found")
    return render_template("transport_products.html", form=form, user_id=session['user_id'], first_name=session['first_name'])

@app.route("/view_transport_logs", methods=["GET", "POST"])
def view_transport_logs():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    form = ViewTransportLogsForm()
    transport_logs = None
    if form.validate_on_submit():
        search_by = form.search_by.data
        product_id = form.product_id.data
        month = form.month.data
        
        query = """SELECT tl.id, tl.product_id, p.name, tl.quantity_transported, tl.log_date, tl.log_time, 
                          CONCAT(u.first_name, ' ', u.last_name) AS full_name 
                   FROM transports_log tl 
                   JOIN products p ON tl.product_id = p.id 
                   JOIN users u ON tl.user_id = u.id"""
        params = []
        
        if search_by == 'id':
            query += " WHERE tl.product_id = %s"
            params.append(product_id)
        elif search_by == 'month':
            query += " WHERE MONTH(tl.log_date) = %s"
            params.append(month)
        elif search_by == 'both':
            query += " WHERE tl.product_id = %s AND MONTH(tl.log_date) = %s"
            params.append(product_id)
            params.append(month)
        
        cur = mysql.connection.cursor()
        cur.execute(query, tuple(params))
        transport_logs = cur.fetchall()
    
    return render_template("view_transport_logs.html", form=form, transport_logs=transport_logs, user_id=session['user_id'], first_name=session['first_name'])

if __name__ == "__main__":
    app.run(debug=True)