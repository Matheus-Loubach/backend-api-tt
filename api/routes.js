import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import { CssSyntaxError } from 'postcss'
import bcrypt from  'bcrypt'
import  jwt  from 'jsonwebtoken'
  
export const router = new Router()


const prisma = new PrismaClient()

//bd recebe os dados
router.get('/tweets', async function(ctx){
 
  const [, token] = ctx.request.headers?.authorization?.split(' ') || []

  if(!token){
      ctx.status = 401
      return
    }
 try{    
     jwt.verify(token, process.env.JWT_SECRET)
     const tweets = await prisma.tweet.findMany({

    //passar os tt// nome do user 
          include: {
          user: true
        }
      })
      ctx.body = tweets
      }catch(error){
        if(typeof error === 'JsonWebTokenError'){

          ctx.status = 401
          return
        }
      
          ctx.status = 500
          return
    
  }
})


//enviar tt
router.post('/tweets', async function(ctx){
  const [, token] = ctx.request.headers?.authorization?.split(' ') || []
  console.log(token)
  if(!token){
      ctx.status = 401
      return
    }
 try{    

  const payload = jwt.verify(token, process.env.JWT_SECRET)

    const tweet = await prisma.tweet.create({
      data: {
        userId: payload.sub,
        text: ctx.request.body.text
      }
    })
  
   ctx.body = tweet
  }catch(error){
    ctx.status = 401
    return
  }

})
//cadastro
router.post('/signup', async function(ctx)
{
  const saltRounds = 10
  const password = bcrypt.hashSync(ctx.request.body.password, saltRounds);

  try{

    const user = await prisma.user.create({
 
      data:{
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password
      }
    })

    const accessToken = jwt.sign({
      sub: user.id
    }, process.env.JWT_SECRET, { expiresIn: '24h'})

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken
    }
    
  }catch(error){
    if(error.meta && !error.meta.target)
    {
    console.log('Cadastro já existe')
    ctx.body = "Email ou Usúario já existe"
    ctx.status = 422
    return
    }
  }
})

//LOGIN
router.get('/login', async function(ctx){
  const [, token] = ctx.request.headers.authorization.split(' ')
  const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':')


  //passa password//se achar o user
  const user = await prisma.user.findUnique({
    where:{ email }
  })
  

  if(!user){
    ctx.status = 404
    return
  }

try{
  //verifica a senha
  const passwordMatch = bcrypt.compareSync(plainTextPassword, user.password)

  //retorna user
  if(passwordMatch){
    const accessToken = jwt.sign({
      sub: user.id
    }, process.env.JWT_SECRET, { expiresIn: '24h'})
  
    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken
    }
  }
}catch(error)
{  if(error.meta && !error.meta.target)
  {
  ctx.status = 404
  console.log('senha errada')
  return
  }
}
 
   
})

// deletar o tweet
router.delete('/tweet/:id', async ctx => {
  const [, token] = ctx.request.headers?.authorization?.split(' ') || []

  if (!token) {
    ctx.status = 401
    return
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET)
    const deleted = await prisma.tweet.delete({
      where: {
        id: ctx.params.id
      }
    })

    ctx.body = deleted
  } catch (error) {
    ctx.status = 401
    return
  }
})