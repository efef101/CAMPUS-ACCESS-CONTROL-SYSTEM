<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CACS | Campus Access Control System</title>

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

    /* =========================
       BACKGROUND
    ========================= */

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
        linear-gradient(
          rgba(15,36,64,0.58),
          rgba(15,36,64,0.84)
        ),
        url('background (1).jpg') center/cover no-repeat;

      filter:blur(8px);
      transform:scale(1.08);
    }

    /* =========================
       MAIN CONTAINER
    ========================= */

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

    /* =========================
       LEFT SIDE
    ========================= */

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

    .left .desc{
      font-size:15px;
      line-height:1.7;

      color:rgba(255,255,255,0.82);

      max-width:500px;
    }

    /* =========================
       RIGHT PANEL
    ========================= */

    .panel{
      padding:44px;

      border-radius:36px;

      background:rgba(255,255,255,0.97);

      border:1px solid rgba(255,255,255,0.8);

      box-shadow:
        0 15px 40px rgba(15,36,64,0.25),
        0 0 35px rgba(88,130,190,0.10);
    }

    .panel-top{
      text-align:center;

      margin-bottom:36px;
    }

    .panel-top img{
      width:92px;
      height:92px;

      object-fit:contain;

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

    /* =========================
       MENU BUTTONS
    ========================= */

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

      padding:18px;

      border-radius:24px;

      background:#f4f7fb;

      border:1px solid #dce4ef;

      color:#16233d;

      transition:
        transform 0.25s ease,
        background 0.25s ease,
        border-color 0.25s ease,
        box-shadow 0.25s ease;
    }

    .btn:hover{
      transform:translateY(-2px);

      background:#ffffff;

      border-color:#6d8fca;

      box-shadow:
        0 8px 24px rgba(58,94,145,0.18);
    }

    .btn:hover .icon{
      background:#eaf1fb;
      border-color:#6d8fca;
      color:#315b96;
      transform:scale(1.04);
    }

    .btn-left{
      display:flex;
      align-items:center;

      gap:18px;
    }

    /* =========================
       SVG ICON
    ========================= */

    .icon{
      width:58px;
      height:58px;

      flex-shrink:0;

      border-radius:16px;

      display:flex;
      justify-content:center;
      align-items:center;

      background:#eef3fa;

      border:1px solid #c7d7ec;

      color:#315b96;

      transition:all 0.25s ease;
    }

    .icon svg{
      width:25px;
      height:25px;

      stroke:currentColor;

      fill:none;

      stroke-width:1.8;

      stroke-linecap:round;
      stroke-linejoin:round;
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

    .arrow{
      width:22px;
      height:22px;

      color:#9aabc2;

      transition:all 0.25s ease;
    }

    .btn:hover .arrow{
      color:#315b96;
      transform:translateX(3px);
    }

    /* =========================
       SUBTLE MY LOGS LINK
    ========================= */

    .logs-link{
      display:flex;
      align-items:center;
      justify-content:center;
      gap:6px;

      width:fit-content;
      margin:20px auto 0;
      padding:6px 12px;

      border-radius:999px;

      font-size:12px;
      text-decoration:none;

      color:#a3b3cc;
      opacity:.75;

      transition:all 0.25s ease;
    }

    .logs-link svg{
      width:14px;
      height:14px;

      stroke:currentColor;
      fill:none;
      stroke-width:1.8;
      stroke-linecap:round;
      stroke-linejoin:round;
    }

    .logs-link:hover,
    .logs-link:focus-visible{
      opacity:1;
      color:#315b96;
      background:#eef3fa;
    }

    /* =========================
       FOOTER
    ========================= */

    .footer{
      margin-top:18px;

      text-align:center;

      font-size:10px;

      color:#a3b3cc;
    }

    /* =========================
       RESPONSIVE
    ========================= */

    @media(max-width:950px){

      html,
      body{
        overflow:auto;
      }

      .container{
        min-height:100vh;
        height:auto;

        padding:25px;
      }

      .dashboard{
        grid-template-columns:1fr;

        max-width:560px;

        gap:25px;
      }

      .left{
        text-align:center;
        padding-left:0;
      }

      .eyebrow{
        margin-left:auto;
        margin-right:auto;
      }

      .left h1{
        font-size:46px;
      }

      .left .desc{
        margin:auto;
      }

      .panel{
        padding:32px;
      }
    }

    @media(max-width:500px){

      .container{
        padding:18px;
      }

      .left h1{
        font-size:38px;
        letter-spacing:-2px;
      }

      .eyebrow{
        padding:7px 12px 7px 7px;
      }

      .eyebrow span{
        font-size:9px;
      }

      .eyebrow .tagline,
      .eyebrow .divider-dot{
        display:none;
      }

      .panel{
        padding:25px;
        border-radius:28px;
      }

      .panel-top h2{
        font-size:26px;
      }

      .btn{
        padding:15px;
      }

      .icon{
        width:52px;
        height:52px;
      }
    }
  </style>
</head>

<body>

<div class="background"></div>

<div class="container">

  <div class="dashboard">

    <!-- LEFT SIDE -->
    <div class="left">

      <div class="eyebrow">

        <span class="mono">
          <img src="logo.png" alt="CTU logo">
        </span>

        <span>Cebu Technological University</span>

        <span class="divider-dot"></span>

        <span class="tagline">Main Campus</span>

      </div>

      <h1>
        Campus Access<br>
        Control System
      </h1>

    </div>


    <!-- RIGHT SIDE -->
    <div class="panel">

      <div class="panel-top">

        <img src="logo.png" alt="Cebu Technological University Logo">

        <h2>CACS Portal</h2>

      </div>


      <div class="menu">

        <!-- LOGIN -->
        <a href="login.php" class="btn">

          <div class="btn-left">

            <div class="icon">

              <!-- Login / Lock SVG -->
              <svg viewBox="0 0 24 24" aria-hidden="true">

                <rect x="4" y="10" width="16" height="10" rx="2"></rect>

                <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>

                <circle cx="12" cy="15" r="1"></circle>

                <path d="M12 16v2"></path>

              </svg>

            </div>

            <div class="btn-text">

              <h4>Login</h4>

            </div>

          </div>

        </a>


        <!-- REGISTER -->
        <a href="register.html" class="btn">

          <div class="btn-left">

            <div class="icon">

              <!-- User Registration SVG -->
              <svg viewBox="0 0 24 24" aria-hidden="true">

                <circle cx="9" cy="8" r="3"></circle>

                <path d="M3 20c.7-3.1 2.7-5 6-5s5.3 1.9 6 5"></path>

                <path d="M17 8v6"></path>

                <path d="M14 11h6"></path>

              </svg>

            </div>

            <div class="btn-text">

              <h4>Register</h4>

            </div>

          </div>

        </a>

      </div>


      <!-- MY LOGS (subtle link) -->
      <a href="my_logs.php" class="logs-link">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M9 6h11"></path>
          <path d="M9 12h11"></path>
          <path d="M9 18h11"></path>
          <circle cx="4.5" cy="6" r="1"></circle>
          <circle cx="4.5" cy="12" r="1"></circle>
          <circle cx="4.5" cy="18" r="1"></circle>
        </svg>
        View My Logs
      </a>


      <div class="footer">

        Cebu Technological University •
        Campus Access Control System • CACS

      </div>

    </div>

  </div>

</div>

</body>
</html>