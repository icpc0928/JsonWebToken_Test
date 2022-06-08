
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenUtils {

    //設置過期時間
    private static final long EXPIRE_DATE = 1000;
    //token密鑰
    private static final String TOKEN_SECRET = "123456";

    //實現簽名方法
    public static String token (String username, String password){

        String token = "";
        try{
            //這裡將username & password 存入token, 在下面的解析中,也會有解析的方法可以獲取到 token裡面的數據
            //token過期的時間
            //過期時間
            Date date = new Date(System.currentTimeMillis() + EXPIRE_DATE);
            //密鑰及加密算法
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            //設置頭部訊息,類型以及簽名所用算法
            Map<String, Object> header = new HashMap<>();
            header.put("typ", "JWT");
            header.put("alg", "HS256");
            //攜帶username, password信息, 存入token, 生成簽名
            token = JWT.create()
                    .withHeader(header)
                    //儲存自己想要留改前端的內容
                    .withClaim("username", username)
                    .withClaim("password", password)
                    //設定到期時間
                    .withExpiresAt(date)
                    .sign(algorithm);

        }catch (Exception e){
            System.out.println(e);
            return null;
        }

        return token;
    }

    //驗證token
    public static boolean verify(String token){
        /**
         * @desc 驗證Token, 通過返回true
         * @params [token]需要校驗的串
         */

        try{
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Token 超時");
        }
        return false;
    }

    //獲取token 信息
    public static void getInfo(String token){
        try{
            DecodedJWT jwt = JWT.decode(token);
            System.out.println("JWT Header: " + jwt.getHeader());
            System.out.println("JWT Token: " + jwt.getToken());
            System.out.println("JWT PayLoad: " + jwt.getPayload());
            System.out.println("JWT Claims: " + jwt.getClaims().toString());
//            return jwt.getClaim("username").asString();

        }catch (Exception e){
            e.printStackTrace();
        }
    }


    //測試
    public static void main(String[] args) throws InterruptedException {
        String username = "leo";
        String password = "1234234";
        String token = token(username, password);
        System.out.println("Token: " + token);
        boolean b = verify(token);
        System.out.println(b);
//        Thread.sleep(1001);
        b = verify(token);
        System.out.println(b);
//        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoibGVvIiwicGFzc3dvcmQiOiI1NTU1NSJ9.mTC5RKkpv4VWV_jyVm6wWfUML545PPldkpSIBGWW7FA";
        getInfo(token);


    }
}
