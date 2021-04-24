const Post=require("../../models/Post");
const checkAuth=require("../../utils/check-auth");
const {UserInputError, AuthenticationError}=require('apollo-server');

module.exports={
    Query:{

    },
    Mutation:{
    createComment: async(parent, {postId,body},context)=>{
        const {username}=checkAuth(context);
        console.log("reached here");
        if(body.trim()===""){
     throw new UserInputError('Empty comment',{
         errors:{
             body:'Comment body must not be empty'
         }
     })
        }

        const post=await Post.findById(postId);
        if(post){
            post.comments.unshift({
                body,
                username,
                createdAt:new Date().toISOString(),
            });
            await post.save();
            return post;
        }
        else throw new UserInputError('Post not found');
    },
    async deleteComment(parent,{postId,commentId},context,info){
        try{
         const {username}=checkAuth(context);
         const post = await Post.findById(postId);
         if(post){
             const commentIndex=post.comments.findIndex(c=>c.id === commentId);
             if(post.comments[commentIndex].username === username){
                 post.comments.splice(commentIndex,1);
                 await post.save();
                 return post;
             }
             else{
                    throw new AuthenticationError('Action not allowed')
             }
         }
         else{
             throw new UserInputError('Post not found');
         }


        }catch(err){
            throw new Error(err);
        }
    }
    }
}