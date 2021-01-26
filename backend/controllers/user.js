const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const emailValidator = require('email-validator');
const passwordValidator = require('password-validator');
const MaskData = require('maskdata');

const User = require('../models/user');

const passwordSchema = new passwordValidator();

passwordSchema
    .is().min(8)
    .is().max(30)
    .has().uppercase()
    .has().lowercase()
    .has().digits()
    .has().not().symbols()
    .has().not().spaces();

exports.signup = (req, res, next) => {
    if (!emailValidator.validate(req.body.email) || !passwordSchema.validate(req.body.password)) {
        return res.status(400).json({message: 'Le mot de passe doit contenir une majuscule, une minuscule et un chiffre. Sa longueur doit être entre 8 et 30 caractères'});
    } else if (emailValidator.validate(req.body.email) || passwordSchema.validate(req.body.password)) {
        const maskedMail = MaskData.maskEmail2(req.body.email);
        bcrypt.hash(req.body.password, 10)
            .then(hash => {
                const user = new User({
                    email: maskedMail,
                    password: hash
                });
                user.save()
                    .then(() => res.status(201).json({message: 'Utilisateur créé !'}))
                    .catch(error => res.status(400).json({error}));
            })
            .catch(error => res.status(500).json({error}));
    }
}

exports.login = (req, res, next) => {
    const maskedMail = MaskData.maskEmail2(req.body.email);
    User.findOne({ email: maskedMail })
        .then(user => {
            if (!user) {
                return res.status(401).json({ error: 'Utilisateur non trouvé !' });
            }
            bcrypt.compare(req.body.password, user.password)
                .then(valid => {
                    if (!valid) {
                        return res.status(401).json({ error: 'Mot de passe incorrect !' });
                    }
                    res.status(200).json({
                        userId: user._id,
                        token: jwt.sign(
                            { userId: user._id },
                            'RANDOM_TOKEN_SECRET',
                            { expiresIn: '24h' }
                        )
                    });
                })
                .catch(error => res.status(500).json({ error }));
        })
        .catch(error => res.status(500).json({ error }));
};