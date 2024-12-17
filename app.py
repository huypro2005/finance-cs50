import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import requests as r
from helpers import apology, login_required, lookup, usd, format_stock_prices
from datetime import datetime
from time import sleep
# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    datas = db.execute('select symbol, sum(shares) shares \
                       from stocks\
                       where user_id = ?\
                       group by symbol', session['user_id'])
    stocks =[]
    cash =0
    for i in range(len(datas)):
        symbol = datas[i]['symbol']
        stock = lookup(symbol)  # Assuming lookup() fetches stock data
        stock_info = {
            'symbol': stock['symbol'],
            'shares': datas[i]['shares'],
            'price': usd(stock['price']),
            'total_price': usd(datas[i]['shares']*stock['price'])
        }
        stocks.append(stock_info)  # Add stock info to the list
        cash += datas[i]['shares']*stock['price']
    data_user = db.execute('select cash from users where id =?', session['user_id'])
    total = data_user[0]['cash'] +cash
    return render_template('index.html', datas = stocks, cash = usd(cash), total = usd(total), flash = flash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        if not symbol:
            return apology('no symbol found')
        
        if not shares:
            return apology('no shares found')
        
        if not shares.isnumeric():
            return apology('shares must be a number')
        
        shares= float(shares)
        
               
        if shares <= 0:
            return apology('shares must be a positive number')
        
        shares = int(shares)
        
        stock = lookup(symbol)
        
        if not stock:
            return apology('Stock not exist')
        
        data_user = db.execute('select * from users where id = ?', session['user_id'])
        cash = data_user[0]['cash']
        amount = stock['price']*shares
        
        if cash < amount:
            return apology('you dont have enough balance')
        
        db.execute('update users set cash = cash - ? where id = ?', amount, session['user_id'])
        db.execute('insert into stocks(user_id, symbol, shares, total_price) values (?, ?, ?, ?)'
                   , session['user_id'],  stock['symbol'], shares, amount)
        flash('Bought!')
        return redirect('/')
       

    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    try:
        histories = db.execute('select * from stocks where user_id = ? order by date_create desc', session['user_id'])
        save = []
        for i in range(len(histories)):
            save.append({
                'symbol': histories[i]['symbol'],
                'shares': histories[i]['shares'],
                'price': usd(histories[i]['total_price']/histories[i]['shares']),
                'date': histories[i]['date_create']
            })
        return render_template('history.html', histories = save)
    except:
        return apology("Access hitory fail.")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")

        ):
            
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == 'POST':
        symbol = (request.form.get('symbol'))
        res = lookup(symbol)
        if not res:
            return apology('not searched!', 400)
        if res :
            return render_template('quoted.html',
                                   name = res['name'],
                                   price =usd( res['price']),
                                   symbol = res['symbol'])
    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    
    if request.method == 'POST':
        user = request.form.get('username')
        password = request.form.get('password')
        password1 = request.form.get('confirmation')
        if not user:
            return apology('no username found')
        if not password:
            return apology('no password found')
        if not password1:
            return apology('no confirmation password found')
        if password != password1:
            return apology('password not same')
        try:
            password_hash = generate_password_hash(password)
            db.execute('insert into users(username, hash) values (?, ?)',user, password_hash)
            rows = db.execute('select* from users where username =?', user)
            session["user_id"] = rows[0]["id"]
            return redirect('/')
        except:
            return apology('Duplicated user')
    else:
        return render_template('register.html')



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    
    if request.method == 'POST':

        symbol = request.form.get('symbol')
        shares = (request.form.get('shares'))
        if not symbol:
            return apology('No symbol found')
        if not shares:
            return apology('No shares found')
        if not shares.isnumeric():
            return apology('shares must be a number')
        
        
               

        shares = int(float(shares))
        stock_owned = db.execute('select sum(shares) shares from stocks where user_id = ? and symbol = ?', session['user_id'], symbol)
    
        if stock_owned[0]['shares'] < shares*(-1):
            return apology('You don\'t have enough shares')
        stock = lookup(symbol)
        if not stock:
            return apology('Stock not exist')
        amount = stock['price'] * shares
        db.execute('update users set cash = cash + ? where id = ?', amount, session['user_id'])
        db.execute('insert into stocks(user_id, symbol, shares, total_price) values (?, ?, ?, ?)', session['user_id'], stock['symbol'], -shares, -amount)
        flash('Sold!')
        return redirect('/')
    stock_owning = db.execute('select sum(shares) shares from stocks where user_id = ?', session['user_id'])
    if not stock_owning[0]['shares'] or stock_owning[0]['shares'] == 0:
        return apology('You don\'t have any shares')
    stocks = db.execute('select symbol from stocks where user_id = ? group by symbol having sum(shares)>0', session['user_id'])
    return render_template('sell.html', stocks = stocks)

@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == 'POST':
        cash = request.form.get('cash')
        if not cash:
            return apology('No cash found')
        cash = int(float(cash))
        db.execute('update users set cash = cash + ? where id = ?', cash, session['user_id'])
        flash('Added cash')
        return redirect('/')
    return render_template('add_cash.html')




if __name__ == '__main__':
    app.run(debug=True)