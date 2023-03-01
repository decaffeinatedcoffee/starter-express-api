const express = require("express");
const app = new express();
require("dotenv").config();
const Keyv = require('keyv');
const keyv = new Keyv(process.env.MONGODB);
keyv.on('error', err => console.log('Connection Error', err));
const CryptoJS = require("crypto-js");
var bcrypt = require('bcrypt');
var AES = require("crypto-js/aes");
let uuid = require('uuid').v4();
var bodyParser = require('body-parser')
const OneSignal = require('onesignal-node');   
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
var cors = require('cors');
app.use(cors());
const client = new OneSignal.Client(process.env.OSID, process.env.OSKEY);

app.post("/register", async function(req, res){
    var email = req.body.email;
    var pass = req.body.pass;
    var username = req.body.username;
    var onesignal = req.body.onesignal;
    var userCount = await keyv.get("userCount");
    if(!userCount){
        userCount = 0;
    }
    let inUse = false;

    for(var i = 1; i < userCount+1; i++){
        let currentUser = await keyv.get(`user${i}`);
        if(currentUser){
            currentUser = JSON.parse(currentUser);
            let dbmail = currentUser.email;
            dbmail = CryptoJS.AES.decrypt(dbmail, process.env.SALT).toString(CryptoJS.enc.Utf8);
            if(dbmail == email){
              res.send(JSON.stringify({"error":true, "data":"error"}));  
              inUse = true;
              return
            } 
        }
    }

      if(inUse == false){
        let userID;
        bcrypt.hash(pass, 10, function(err, hash) {
        pass = hash;
        userID = uuid.replace(/-/g, '').slice(10, 16).toUpperCase();
        userID = CryptoJS.AES.encrypt(userID, process.env.SALT).toString();
        username = CryptoJS.AES.encrypt(username, process.env.SALT).toString();
        email = CryptoJS.AES.encrypt(email, process.env.SALT).toString();
        onesignal = CryptoJS.AES.encrypt(onesignal, process.env.SALT).toString();
        let user = {"username":username, "email":email, "pass":pass, "OneSignal":onesignal, "userID":userID, compras:[], credits:0};
        keyv.set(`user${parseInt(userCount)+1}`, JSON.stringify(user));
        keyv.set("userCount", parseInt(userCount) + 1);
        res.send({"error":false, "data":"success"});
          return
      });
      }
})


  app.post("/login", async function(req,res){
    let mail = req.body.email;
    let pass = req.body.pass;
    var userCount = await keyv.get("userCount");
    var userfound = false;
    for(var i = 1; i < userCount+1; i++){
      let currentUser = await keyv.get(`user${i}`);
      if(currentUser){
        currentUser = JSON.parse(currentUser);
        let dbmail = CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
        if(dbmail == mail){
          userfound = true;
          bcrypt.compare(pass, currentUser.pass, function(err, result) {
            if(result == true){
              let userToken = uuid.replace(/-/g, '').toString();
            res.send(JSON.stringify({error:false, data:{token:userToken, mail:mail}}));
            bcrypt.hash(userToken, 10, function(err, hashToken) {
            currentUser.loginToken = hashToken
            keyv.set(`user${i-1}`, JSON.stringify(currentUser));
              return
          });
            }else{
              res.send(JSON.stringify({error:true, data:"Senha inválida"}));
             return;
           }
         });
        }
      }
    }
    if(userfound == false){
    res.send(JSON.stringify({error:true, data:"Usuário invalido"}));
    }
  })

  


   app.post("/getuser", async function(req,res){
    let email = req.body.email;
    let token = req.body.token;
    let onesignal = req.body.onesignal;
    var userCount = await keyv.get("userCount");

    for(var i = 1; i < userCount+1; i++){
      let currentUser = await keyv.get(`user${i}`);
      if(currentUser){
        currentUser = JSON.parse(currentUser);
        let dbmail =  CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
        if(dbmail == email){
          bcrypt.compare(token, currentUser.loginToken, function(err, result) {
            if(result == true){
              let username = CryptoJS.AES.decrypt(currentUser.username, process.env.SALT).toString(CryptoJS.enc.Utf8);
              let userID = CryptoJS.AES.decrypt(currentUser.userID, process.env.SALT).toString(CryptoJS.enc.Utf8);
              let userMail = CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
              onesignal = CryptoJS.AES.encrypt(onesignal, process.env.SALT).toString();
              let userCredits = currentUser.credits;
              if(!userCredits){
                userCredits = 0;
              }
              currentUser.OneSignal = onesignal;
              keyv.set(`user${i-1}`, JSON.stringify(currentUser));
              let compras = [];
              if(currentUser.compras){
              for(var x = 0; x < currentUser.compras.length; x++){
               compras.push(currentUser.compras[x]);
              }
            }
               compras.reverse();
              
               res.send(JSON.stringify({error:false, data:{user:{username:username, userID:userID, email:userMail}, transactions:{credits:userCredits, compras:compras}}}));
               return
        }else{
          res.send(JSON.stringify({error:true, data:"tokenerr"}));
          return
        }
      });
      }
    }
  }
});
  

app.post("/edituser", async function(req,res){
  let pass = req.body.pass;
  let currentMail = req.body.currentMail;
  let username = req.body.username;

  var userCount = await keyv.get("userCount");
    for(var i = 1; i < userCount+1; i++){
      let currentUser = await keyv.get(`user${i}`);
      if(currentUser){
        currentUser = JSON.parse(currentUser);
        let userMail = CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
        if(userMail == currentMail){
          bcrypt.compare(pass, currentUser.pass, function(err, result) {
            if(result == true){
           username = CryptoJS.AES.encrypt(username, process.env.SALT).toString();
           currentUser.username = username;
           keyv.set(`user${i-1}`, JSON.stringify(currentUser));
           res.send(JSON.stringify({error:false, data:"Alterado com Sucesso"}));
            }else{
              res.send(JSON.stringify({error:true, data:"wrongpass"}));
            }
        });
      }
    }
    }
})



app.post("/deleteuser", async function(req,res){
  let pass = req.body.pass;
  let currentMail = req.body.currentMail;

  var userCount = await keyv.get("userCount");
    for(var i = 1; i < userCount+1; i++){
      let currentUser = await keyv.get(`user${i}`);
      if(currentUser){
        currentUser = JSON.parse(currentUser);
        let userMail = CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
        if(userMail == currentMail){
          bcrypt.compare(pass, currentUser.pass, function(err, result) {
            if(result == true){
            keyv.delete(`user${i-1}`)
           res.send(JSON.stringify({error:false, data:"done"}));
            }else{
              res.send(JSON.stringify({error:true, data:"wrongpass"}));
            }
        });
      }
    }
    }
})



app.post("/editpass", async function(req,res){
  let pass = req.body.pass;
  let currentMail = req.body.currentMail;
  let newpass = req.body.newpass

  var userCount = await keyv.get("userCount");
    for(var i = 1; i < userCount+1; i++){
      let currentUser = await keyv.get(`user${i}`);
      if(currentUser){
        currentUser = JSON.parse(currentUser);
        let userMail = CryptoJS.AES.decrypt(currentUser.email, process.env.SALT).toString(CryptoJS.enc.Utf8);
        if(userMail == currentMail){
          bcrypt.compare(pass, currentUser.pass, function(err, result) {
            if(result == true){
              bcrypt.hash(newpass, 10, function(err, hash) {
              currentUser.pass = hash;
              keyv.set(`user${i-1}`, JSON.stringify(currentUser));
              res.send(JSON.stringify({error:false, data:"done"}));
              })
            }else{
              res.send(JSON.stringify({error:true, data:"wrongpass"}));
            }
        });
      }
    }
    }
})


app.post("/getusercredits", async function(req,res){
  let code = req.body.code;
  var userCount = await keyv.get("userCount");
  for(var i = 1; i < userCount+1; i++){
    let currentUser = await keyv.get(`user${i}`);
    if(currentUser){
      currentUser = JSON.parse(currentUser)
      let id = CryptoJS.AES.decrypt(currentUser.userID, process.env.SALT).toString(CryptoJS.enc.Utf8);
      if(id.toLowerCase() == code.toLowerCase()){
        if(currentUser.credits == undefined){
          currentUser.credits = 0;
        }
        res.send(JSON.stringify({data:currentUser.credits}));
        return;
      }
    }
  }
  res.send(JSON.stringify({data:"err"}));
})


app.post("/savepurchase", async function(req,res){
  let code = req.body.code;
  let data = req.body.data;
  if(!data.descontos){
    data.descontos = 0;
  }
  var userCount = await keyv.get("userCount");
  for(var i = 1; i < userCount+1; i++){
    let currentUser = await keyv.get(`user${i}`);
    if(currentUser){
      currentUser = JSON.parse(currentUser)
      let id = CryptoJS.AES.decrypt(currentUser.userID, process.env.SALT).toString(CryptoJS.enc.Utf8);
      let osIDs = CryptoJS.AES.decrypt(currentUser.OneSignal, process.env.SALT).toString(CryptoJS.enc.Utf8);
      if(id.toLowerCase() == code.toLowerCase()){
      if(data){
        if(currentUser.compras){
      currentUser.compras.push(data);
        }else{
          currentUser.compras = [data];
        }
      let desconto = Math.round(parseInt(data.total) / 10);
      currentUser.credits = desconto;
      keyv.set(`user${i}`, JSON.stringify(currentUser));
      
const notification = {
  contents: {
    'pt': `Obrigado pela sua compra! ${desconto} créditos foram adicionados ao seu balanço.`,
    'en': `Thank you for your purchase! ${desconto} credits were added to your balance.`,
  },
 include_player_ids: [osIDs],
};
client.createNotification(notification);
      res.send(JSON.stringify({data:"done"}));
      return
      }else{
        res.send(JSON.stringify({data:"err"}));
        return
      }
      }
    }
  }
  res.send(JSON.stringify({data:"err"}));
})



app.listen("5000" || "80");
