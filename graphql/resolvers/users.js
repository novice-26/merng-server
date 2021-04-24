const User=require('../../models/User');
const {SECRET_KEY}=require('../../config');
const {validateRegisterInput,validateLoginInput} = require('../../utils/validators');
const {UserInputError}=require('apollo-server');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');

function generateToken(user){
return jwt.sign({id:user.id,
    email:user.email,
    username:user.username,
 },SECRET_KEY,{expiresIn:'1hr'});
}

module.exports={
    Mutation:{
        async register(parent,{registerInput:{username="",email="",password="",confirmPassword=""}},context,info){
        //TODO:  VALIDATE

        const {valid,errors}=validateRegisterInput(username,email,password,confirmPassword);

        if(!valid){
            throw new UserInputError('Errors',{errors});
        }
        const user = await User.findOne({username});
        if(user){
            throw new UserInputError('Username is taken',{
                errors:{
                    username:'This username is taken'
                }
            });
        }
        password=await bcrypt.hash(password,12);
        const newuser= new User({
          email,
          username,
          password,
          createdAt:new Date().toISOString()
        });
        const res = await newuser.save();
        const token=generateToken(res);

     return {
         ...res._doc,
         id:res._id,
         token
     }
        },

    async login(_,{username,password},context,info){
        const {errors,valid}=validateLoginInput(username,password);
        if(!valid){
            throw new UserInputError('Erros',{errors});
        }
        const user=await User.findOne({username});

       if(!user){
           errors.general='User not found';
           throw new UserInputError('User not found',{errors})
       }
       const match=await bcrypt.compare(password,user.password);
       if(!match){
        errors.general='Wrong credentials';
        throw new UserInputError('Wrong credentials',{errors});
       }
       const token=generateToken(user);
       return {
        ...user._doc,
        id:user._id,
        token
    }

    }
    }
}