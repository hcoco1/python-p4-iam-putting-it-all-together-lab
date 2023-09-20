
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    serialize_rules = ('-recipes.user', '-_password_hash',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String , unique=True, nullable=False) 
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    _password_hash = db.Column(db.String)
    
    recipes = db.relationship('Recipe', backref='user', lazy=True)
    



    # Using the hybrid_property decorator, which allows the creation of complex read/write properties for SQLAlchemy models
    # When you try to access this property, an AttributeError is raised.
    # This ensures that the password hash can't be directly accessed.
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    # This decorator allows the setting of the _password_hash attribute.
    # Whenever you try to set a value to password_hash, this method will be called.
    @password_hash.setter
    def password_hash(self, password):
        # Generating a password hash using bcrypt
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        # Saving the password hash (after decoding it to string format) to the private attribute _password_hash
        self._password_hash = password_hash.decode('utf-8')

    # A method to authenticate a given password against the stored password hash
    def authenticate(self, password):
        # Returns True if the given password matches the stored hash, otherwise returns False.
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

 
    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50'),
    )
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    
    def __repr__(self):
        return f'Recipe {self.title}, ID: {self.id}'