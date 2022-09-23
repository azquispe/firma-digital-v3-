package com.ganaseguros.apifirmadorv3.security;

public class RSA_for_PIN {
    public static final String RSA_PRIVATE="-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCm2GL0hylMvhOuEqmVA1xjMpCZ\n" +
            "xZ8pSDctLWyYvouN9U7S5eWY1quhgtMj2OGonxRT3rZsLNQfvnans3qLfyvWhzCOwXBm5y/E6/It\n" +
            "rlp9UjiGn3xBe9pPo6SQ4aHQXAAkyH95eGBLPPgMnBHDHQezpRsVijZmuXfpixbtr/xKRqYuCImK\n" +
            "sruGIubgzvJjco66JDoclcAnfX0OxKcniiTI5Lb6vT1QauIKsqVZ+w52wXH4/dnlpqfXvoikdV1Z\n" +
            "iKgNA4A8riNVyYcBvGNDVBArILN46vdetLIPgxNvCwdFnaBsAfhJcHj/2lsxjWgg0/ktBMKuXNkY\n" +
            "Bc45PwmUOtvnAgMBAAECggEBAKRxzkaZGVmsVpVRi5d1co/K/L6zC0aTCN8cUFbUJ5RJXeF7+ioE\n" +
            "G7Ha0eQZFYEvGcf4UPCZ1pFbFnP/8B6hv0F4iaGKgxDJeEmtDEt9925hpZj6hGu+eNPZxI+P8/77\n" +
            "TqDyhMHipXZCp3E2OkOGz1p+tw0p5qik0M1866JlvFIva8yW4YEjaIaa1VV2L2NIT2oIndNm3zpc\n" +
            "LucuBBX+JIZawIwajh2FrWX56xWNNqglw5lSpbb7W+aPlO1x4m7rtRPNO0Pt9kGnHStjVG38mgYZ\n" +
            "Ju3ypvZkToqUkkz7DYW4+AV0s2tbcwhjg0MQ/oBBtxujJsgl8C2ioHLQkodsonECgYEA3EsMYiHI\n" +
            "EjCHgGFeND5GY9QwFKrhFVXCiYsYy5i799Qr9Y3K2Y/nvOgxxfqgcukVKKs6wnSScN0tNeu8aLCV\n" +
            "6wwcxs6e77OMkqN98FVOEgorazx7JZ5LT3Ev6cVDF/b4znt6tUVHUxGW24MMSjzBJHWsISRpilBo\n" +
            "23sjxa7Rsl0CgYEAweOLiOmtjMyX35SxbVBFDcZyLVa8u98/Rywk3ZAs/VL0OVlfQiK8ylS4Vmfj\n" +
            "t96BTWO1msa4Rccad+JxqnUZ0Mw6mP2H55jU+OyBbZMABifLQpSGX9YyRud1J92dT/eL1kQFxajU\n" +
            "NPvQ0g0EpEtixYIIMSEEd5g5xbkBeac5KxMCgYEAvVJWMyP7MP66BTAo6Nc4YWUjaS+uP0qz5MdB\n" +
            "KQB7UrLqkJ8qXS3aqDQZSp9pMzhzsb7uwd2zWQIMb9HH22UfgqCnPoimeTSitAeEHX8CmGhbBk81\n" +
            "OpA/AugwmESqs7bR/4qJW65NbOup7b9DWa27A92Jb/Y+KduPMkky5hqnJxUCgYBPJFFthmzn3w9T\n" +
            "HP+7bhtxvwIWDaSmTz8mDxfRNKuYj8bOrfNbLJDBSgmgg3GJORKwgzW6wsiu+tGMA+t/t6Lc/rAg\n" +
            "iMRzvYeZP/iowGsvGAk42SVscyM8m/fPWP+Ah7wVrthoUTylj/Ax/Uxav8bGdghf/Wk0Y/eZBKZc\n" +
            "gOyt7wKBgQCx0CZ96o52AuEXSTgOhSXG/7XS5LvKoy87vgVpg+QJbbZpcM3qYhAjCCOm0GjyBkPm\n" +
            "2ogmyA+S1rVrw/SdbSX1QScC3rNfBajTiOmClaG1Y7RoofL0jndfMMDlQDS/3chjr1t822kCw4k3\n" +
            "O3d3epbFNFfw0aJbf+scqAnhl+FF8A==\n" +
            "-----END PRIVATE KEY-----";


    // esta lllave publica debe usar la app de escritorio el cual cifra el PIN
    /*public static final String RSA_PUBLIC="-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApthi9IcpTL4TrhKplQNcYzKQmcWfKUg3\n" +
            "LS1smL6LjfVO0uXlmNaroYLTI9jhqJ8UU962bCzUH752p7N6i38r1ocwjsFwZucvxOvyLa5afVI4\n" +
            "hp98QXvaT6OkkOGh0FwAJMh/eXhgSzz4DJwRwx0Hs6UbFYo2Zrl36YsW7a/8SkamLgiJirK7hiLm\n" +
            "4M7yY3KOuiQ6HJXAJ319DsSnJ4okyOS2+r09UGriCrKlWfsOdsFx+P3Z5aan176IpHVdWYioDQOA\n" +
            "PK4jVcmHAbxjQ1QQKyCzeOr3XrSyD4MTbwsHRZ2gbAH4SXB4/9pbMY1oINP5LQTCrlzZGAXOOT8J\n" +
            "lDrb5wIDAQAB\n" +
            "-----END PUBLIC KEY-----";*/
}
