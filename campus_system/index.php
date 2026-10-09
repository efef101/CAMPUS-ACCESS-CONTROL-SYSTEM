<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>CACS</title>

  <style>

  *{
    margin:0;
    padding:0;
    box-sizing:border-box;
  }

  html,
  body{
    width:100%;
    height:100%;
    overflow:hidden;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    background:#fafbfd;
    color:#16233d;
  }

  body{
    position:relative;
  }

  .background{
    position:fixed;
    inset:0;
    z-index:0;
  }

  .background::before{
    content:'';
    position:absolute;
    inset:-30px;

    background:
      linear-gradient(rgba(15,36,64,0.55), rgba(15,36,64,0.80)),
      url('background (1).jpg') center/cover no-repeat;

    filter:blur(8px);
    transform:scale(1.08);
  }

  .container{
    position:relative;
    z-index:2;
    width:100%;
    height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:30px;
  }

  .dashboard{
    width:100%;
    max-width:1200px;
    display:grid;
    grid-template-columns:1fr 560px;
    align-items:center;
    gap:40px;
  }

  .left{
    padding-left:10px;
  }

  .eyebrow{
    display:inline-flex;
    align-items:center;
    gap:10px;
    padding:8px 16px 8px 8px;
    border-radius:999px;
    background:rgba(255,255,255,0.10);
    border:1px solid rgba(255,255,255,0.22);
    backdrop-filter:blur(6px);
    margin-bottom:22px;
  }

  .eyebrow .mono{
    width:28px;
    height:28px;
    border-radius:50%;
    overflow:hidden;
    background:#ffffff;
    display:flex;
    align-items:center;
    justify-content:center;
  }

  .eyebrow .mono img{
    width:100%;
    height:100%;
    object-fit:cover;
  }

  .eyebrow span{
    font-size:12px;
    font-weight:700;
    letter-spacing:0.16em;
    text-transform:uppercase;
    color:#ffffff;
  }

  .eyebrow .divider-dot{
    width:4px;
    height:4px;
    border-radius:50%;
    background:rgba(255,255,255,0.4);
  }

  .eyebrow .tagline{
    font-size:11px;
    font-weight:500;
    letter-spacing:0.04em;
    text-transform:none;
    color:rgba(255,255,255,0.65);
  }

  .left h1{
    font-size:64px;
    font-weight:700;
    line-height:0.95;
    letter-spacing:-3px;
    margin-bottom:18px;
    color:#ffffff;
  }

  @media(max-width:950px){
    .eyebrow{
      margin-left:auto;
      margin-right:auto;
    }
  }

  .left .desc{
    font-size:15px;
    line-height:1.7;
    color:rgba(255,255,255,0.82);
    max-width:500px;
  }


  .panel{
    padding:44px;
    border-radius:36px;
    background:#ffffff;
    border:1px solid #dce4ef;
    box-shadow:0 15px 40px rgba(15,36,64,0.25);
  }

  .panel-top{
    text-align:center;
    margin-bottom:36px;
  }

  .panel-top img{
    width:92px;
    margin-bottom:16px;
    border-radius:18px;
  }

  .panel-top h2{
    font-size:30px;
    margin-bottom:6px;
    color:#16233d;
  }

  .panel-top p{
    font-size:14px;
    color:#8a9bb5;
  }

  .menu{
    display:flex;
    flex-direction:column;
    gap:18px;
  }

  .btn{
    display:flex;
    align-items:center;
    justify-content:space-between;
    text-decoration:none;
    padding:22px;
    border-radius:24px;
    background:#f4f7fb;
    border:1px solid #dce4ef;
    color:#16233d;
    transition:all 0.25s;
  }

  .btn:hover{
    transform:translateY(-2px);
    background:#fffdf5;
    border-color:#f0b429;
    box-shadow:0 8px 24px rgba(240,180,41,0.25);
  }

  .btn:hover .icon{
    background:#fef3d6;
    border-color:#f0b429;
  }

  .btn-left{
    display:flex;
    align-items:center;
    gap:18px;
  }

  .icon{
    width:58px;
    height:58px;
    border-radius:16px;
    display:flex;
    justify-content:center;
    align-items:center;
    background:#eef3fa;
    border:1px solid #c7d7ec;
    font-size:24px;
    transition:all 0.25s;
  }

  .btn-text h4{
    font-size:17px;
    font-weight:600;
    margin-bottom:4px;
    color:#16233d;
  }

  .btn-text p{
    font-size:13px;
    color:#8a9bb5;
  }

  .footer{
    margin-top:18px;
    text-align:center;
    font-size:10px;
    color:#a3b3cc;
  }

  @media(max-width:950px){

    .dashboard{
      grid-template-columns:1fr;
      max-width:450px;
    }

    .left{
      text-align:center;
      padding-left:0;
    }

    .left h1{
      font-size:46px;
    }

    .left .desc{
      margin:auto;
    }
  }

  </style>
</head>

<body>

<div class="background"></div>

<div class="container">

  <div class="dashboard">

    <div class="left">

      <div class="eyebrow">
        <span class="mono"><img src="logo.png" alt="CTU logo"></span>
        <span>Cebu Technological University</span>
        <span class="divider-dot"></span>
        <span class="tagline">Main Campus</span>
      </div>

      <h1>
        Campus Access<br>
        Control System
      </h1>

    </div>

    <div class="panel">

      <div class="panel-top">

        <img src="logo.png">

        <h2>CACS Portal</h2>

        
      </div>

      <div class="menu">

        <a href="login.php" class="btn">

          <div class="btn-left">

            <div class="icon">🔑</div>

            <div class="btn-text">
              <h4>Login</h4>
             
            </div>

          </div>

        </a>

        <a href="register.html" class="btn">

          <div class="btn-left">

            <div class="icon">🎓</div>

            <div class="btn-text">
              <h4>Register</h4>
            </div>

          </div>

        </a>

      </div>

      <div class="footer">
        Cebu Technological University • Campus Access Control System • CACS
      </div>

    </div>

  </div>

</div>

</body>
</html>