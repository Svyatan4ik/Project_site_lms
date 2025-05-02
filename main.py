from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)


# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    recipes = db.relationship('Recipe', backref='author', lazy=True)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100))  # Это поле должно быть
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/')
def index():
    recipes = Recipe.query.all()
    return render_template('index.html', recipes=recipes)


@app.route('/create-recipe', methods=['GET', 'POST'])
def create_recipe():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Обработка загрузки файла
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = f"uploads/{filename}"
        else:
            image_path = None

        recipe = Recipe(
            title=request.form['title'],
            ingredients=request.form['ingredients'],
            instructions=request.form['instructions'],
            image=image_path,
            author_id=session['user_id']
        )
        db.session.add(recipe)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('create_recipe.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        username = request.form['username']

        if password != confirm_password:
            return "Passwords don't match"

        if User.query.filter_by(email=email).first():
            return "Email already exists"

        hashed_password = generate_password_hash(password)
        user = User(email=email, password_hash=hashed_password, username=username)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))

        return "Invalid credentials"

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/my-recipes')
def my_recipes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    recipes = Recipe.query.filter_by(author_id=session['user_id']).all()
    return render_template('my_recipes.html', recipes=recipes)


@app.route('/edit-recipe/<int:recipe_id>', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    recipe = Recipe.query.get_or_404(recipe_id)

    # Проверяем, что рецепт принадлежит текущему пользователю
    if recipe.author_id != session['user_id']:
        return "У вас нет прав для редактирования этого рецепта", 403

    if request.method == 'POST':
        recipe.title = request.form['title']
        recipe.ingredients = request.form['ingredients']
        recipe.instructions = request.form['instructions']

        # Обновляем изображение, если загружено новое
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            recipe.image = f"uploads/{filename}"

        db.session.commit()
        return redirect(url_for('my_recipes'))

    return render_template('edit_recipe.html', recipe=recipe)


@app.route('/delete-recipe/<int:recipe_id>', methods=['POST'])
def delete_recipe(recipe_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    recipe = Recipe.query.get_or_404(recipe_id)

    if recipe.author_id != session['user_id']:
        return "У вас нет прав для удаления этого рецепта", 403

    # Удаляем связанное изображение
    if recipe.image:
        try:
            os.remove(os.path.join(app.static_folder, recipe.image))
        except:
            pass

    db.session.delete(recipe)
    db.session.commit()
    return redirect(url_for('my_recipes'))


@app.route('/recipe/<int:recipe_id>')
def view_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template('recipe_detail.html', recipe=recipe)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)