const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');


// name, email, photo, password, passwordConfirm

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'A user must have a name'],
        // unique: true,
        // maxLength: [40, 'A user name must have less or equal then 40 characters'],
        // minlength: [5, 'A user name must have more or equal then 5 characters'],        
    },
    email: {
        type: String,
        required: [true, 'Please provide your email'],
        unique: true,
        lowercase: true,
        // maxLength: [40, 'A user email must have less or equal then 40 characters'],
        // minlength: [5, 'A user email must have more or equal then 5 characters'],
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    photo: String,
    password: {
        type: String,
        required: [true, 'A user must have a password'],
        // maxLength: [40, 'A user password must have less or equal then 40 characters'],
        minlength: [8, 'A user password must have more or equal then 8 characters'],
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password'],
        validate: {
            // This only works on CREATE and SAVE!!!
            validator: function(el){
                return el === this.password;
            },
            message: 'Passwords are not the same!'
        }
    }
});

userSchema.pre('save', async function(next) {
    // Only run this function if password was modified
    if(!this.isModified('password')) return next();

    // Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, 12);

    // Deletes the password confirm
    this.passwordConfirm = undefined;
    next();
});

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
    return bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);

module.exports = User; 