<!-- <?php
      // Simple LFI here, not meant to be a major blocker to the challenge
      $file = $_GET["page"];
      if (!empty($file)) {
        echo "<pre>";
        echo file_get_contents('./'.$file);
        echo "</pre>";
      }

      ?> -->

<html>

<head>
  <title>Whale Blog</title>
  <!-- Dev Notes #1
      I wonder if we will deploy this at whale-blog.duc.tf or at whale-endpoint.duc.tf

    DDDDDDDDDDDDD             OOOOOOOOO             CCCCCCCCCCCCCKKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEERRRRRRRRRRRRRRRRR   
    D::::::::::::DDD        OO:::::::::OO        CCC::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::::::::::::R  
    D:::::::::::::::DD    OO:::::::::::::OO    CC:::::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::RRRRRR:::::R 
    DDD:::::DDDDD:::::D  O:::::::OOO:::::::O  C:::::CCCCCCCC::::CK:::::::K   K::::::KEE::::::EEEEEEEEE::::ERR:::::R     R:::::R
      D:::::D    D:::::D O::::::O   O::::::O C:::::C       CCCCCCKK::::::K  K:::::KKK  E:::::E       EEEEEE  R::::R     R:::::R
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K:::::K K:::::K     E:::::E               R::::R     R:::::R
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K::::::K:::::K      E::::::EEEEEEEEEE     R::::RRRRRR:::::R 
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K:::::::::::K       E:::::::::::::::E     R:::::::::::::RR  
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K:::::::::::K       E:::::::::::::::E     R::::RRRRRR:::::R 
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K::::::K:::::K      E::::::EEEEEEEEEE     R::::R     R:::::R
      D:::::D     D:::::DO:::::O     O:::::OC:::::C                K:::::K K:::::K     E:::::E               R::::R     R:::::R
      D:::::D    D:::::D O::::::O   O::::::O C:::::C       CCCCCCKK::::::K  K:::::KKK  E:::::E       EEEEEE  R::::R     R:::::R
    DDD:::::DDDDD:::::D  O:::::::OOO:::::::O  C:::::CCCCCCCC::::CK:::::::K   K::::::KEE::::::EEEEEEEE:::::ERR:::::R     R:::::R
    D:::::::::::::::DD    OO:::::::::::::OO    CC:::::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::R     R:::::R
    D::::::::::::DDD        OO:::::::::OO        CCC::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::R     R:::::R
    DDDDDDDDDDDDD             OOOOOOOOO             CCCCCCCCCCCCCKKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEERRRRRRRR     RRRRRRR or is it?
-->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BmbxuPwQa2lc/FVzBcNJ7UAyJxM6wuqIj61tLrc4wSX0szH/Ev+nYRRuWlolflfl" crossorigin="anonymous">
  <style>
    body {
      background-image: url('whale.jpg');
    }

    .content {
      background: rgba(256, 256, 256, 0.7);
      padding: 10px;
      margin-top: 50px;
    }
  </style>

</head>

<body>
  <div class="container">
    <div class="row justify-content-center content">
      <h1>My story about whaless</h1>
      <iframe width="560" height="315" src="https://www.youtube.com/embed/xFPoIU5iiYQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
      <p>
        I hope you the story about whales, one of my friends was all like, "GEEE k eeeeeeh" it was okay,
      </p>


      <h3>Whales a story.</h3>
      <p>
        Whales are cool, they exist and they are pretty big. Some of them are bigger than other whales. Some of the whales swim in the water. Actually I think most of the whales swim in the water. Water is a medium of which whales can swim through. Water is made up of 2 Parts Oxygen and 1 Part Hydrogen. Whales like this because they can swim in and it is where we live.
      </p>

      <p>
        As for my second point, whales come in all shapes and sizes. They also do this thing where they swim to the top of the water (in the ocean usually) and then do a big jump at the top where they move from the water into the air. Air is made out of gas and does not have water on it. Because of this the whales realise that they cannot stay above the water for long because they must live in water so they drop back into the water. This is also due to gravity. Gravity is the force the pushes whales to the ground.
      </p>

      <p>
        Whales also have a big hole on top of their body. The hole is called their "Whale Hole" when the whale has a lot of water in their body they must get rid of it. They do this by doing a big spurt and lots of water comes out. This is because they can't have too much water in their body because they are already surrounded by water.
      </p>

      <p>
        In conclusion, I think that whales are cool and great and they do cool stuff. Sometimes they exists and sometimes they don't and thats okay. Because if whales are real. Then so are we.
      </p>

      <p>
        Kind Regards,
      </p>
      <p>
        Whale
      </p>

      <h2>Some Blog Links</h2>
      <ul>
        <li><a href="?page=page1">Blog 1</a></li>
        <li><a href="?page=page2">Blog 2</a></li>
      </ul>
    </div>

  </div>

</body>

</html>