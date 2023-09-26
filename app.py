from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, RegisterForm, FeedbackForm

from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///hash_assignment"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

connect_db(app)

@app.route('/')
def home_page():
     return render_template('index.html')

@app.route('/secrets')
def show_secrets():
     if "user_id" not in session:
          flash("Please login first!")
          return redirect('/')
     return render_template('secrets.html')


@app.route('/register', methods = ['GET', 'POST'])
def register_user():
     form = RegisterForm()
     if form.validate_on_submit():
          username = form.username.data
          password = form.password.data
          email = form.email.data
          first_name = form.first_name.data 
          last_name = form.last_name.data 
          ## Implement what to do if new user was trying to taken username thats already there
          new_user = User.register(username, password, email, first_name, last_name)
          db.session.add(new_user)
          db.session.commit()
          session['user_id'] = new_user.id
          flash ('Thank you for creating account')
          return redirect('/login')
     return render_template('register.html', form=form)

# @app.route('/login', methods = ["GET", 'POST'])
# def login_page():
#      form = UserForm()
#      if form.validate_on_submit():
#           username = form.username.data
#           password = form.password.data

#           user = User.authenticate(username, password)
#           if user:
#                flash(f'Welcome back, {user.username}!')
#                session['user_id'] = user.id
#                return redirect('/users/<string:username>')
#           else:
#                form.username.errors = ['Invalid username/password.']
#      return redirect('/users/<string:username>', form=form)

@app.route('/login', methods=["GET", 'POST'])
def login_page():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f'Welcome back, {user.username}!')
            session['user_id'] = user.id
            return redirect(f'/users/{username}')  # Updated URL format
        else:
            form.username.errors = ['Invalid username/password.']
    return render_template('login.html', form=form)

##Note to self for routing. We are getting the information being passed by the login data
##The informatino from the login data is what "username" turns into


@app.route('/users/<string:username>', methods=["GET"])
def user_page(username):
    if "user_id" not in session:
        flash("Please login first!")
        return redirect('/')
    user = User.query.filter_by(username=username).first()
    feedback = Feedback.query.filter_by(user_id=user.id).all()
    return render_template ('secrets.html', user=user, feedback=feedback)

@app.route('/users/<string:username>/feedback/add', methods = ['GET', 'POST'])
def add_feedback(username):
     if "user_id" not in session:
          flash("Please Login as Correct User!")
          return redirect('/')
     user = User.query.filter_by(username=username).first()
     form = FeedbackForm()
     all_feedback = Feedback.query.all()
     if form.validate_on_submit():
          text = form.text.data
          new_feedback = Feedback(text=text, user_id=session['user_id'])
          db.session.add(new_feedback)
          db.session.commit()
          flash('Thank you for your feedback!')
          redirect('/users/<string:username>/')
     return render_template ('feedback.html', form=form, user=user, all_feedback=all_feedback)


@app.route('/users/<string:username>/feedback/edit', methods = ['GET', 'POST'])
def edit_feedback(username):
    if "user_id" not in session:
        flash("Please Login as Correct User!")
        return redirect('/')
    user = User.query.filter_by(username=username).first()
    form = FeedbackForm()
    all_feedback = Feedback.query.all()
    if form.validate_on_submit():
        text = form.text.data
        new_feedback = Feedback(text=text, user_id=session['user_id'])
        db.session.add(new_feedback)
        db.session.commit()
        flash('Thank you for your feedback!')
        redirect('/users/<string:username>/')
    return render_template ('edit_feedback.html', form=form, user=user, all_feedback=all_feedback)

@app.route('/feedback/<int:id>/delete', methods=["POST"])
def delete_feedback(id):
    """Delete FEEDBACK"""
    feedback = Feedback.query.get_or_404(id)
    if feedback.user_id == session['user_id']:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted")
        return redirect('/users/<string:username>/feedback/add')
    flash("YOU CANT DO THAT")
    return redirect('/users/<string:username>/feedback/add')

@app.route('/logout')
def logout_user():
     session.pop('user_id')
     return redirect('/')


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    
