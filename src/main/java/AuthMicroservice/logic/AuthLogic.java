package AuthMicroservice.logic;

import AuthMicroservice.DTO.TokenDTO;
import AuthMicroservice.entity.User;
import AuthMicroservice.repo.IUserRepo;
import AuthMicroservice.security.PasswordHashing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class AuthLogic {
    private final IUserRepo userRepo;

    @Value("${security.jwt.token.secret-key}")
    private String secretKey;
    @Value("${security.jwt.token.expire-length}")
    private long validityInMilliseconds;

    private TokenDTO token = new TokenDTO();

    @Autowired
    public AuthLogic(IUserRepo userRepo) {
        this.userRepo = userRepo;
    }

    public TokenDTO login(User user) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        List<User> generalUserList = userRepo.findAll();
        for (User user1 : generalUserList)
        {
            if (user.getUname().equals(user1.getUname()) && PasswordHashing.validatePassword(user.getPassword(), user1.getPassword()))
            {
                token.setToken(this.createToken(user1.getUname(), user1.getId()));
                return token;
            }
        }
        return null;
    }

    public User register(User user) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (user.getUname().isBlank() || user.getPassword().isBlank())
            return null;
        List<User> userList = userRepo.findAll();
        for (User user1 : userList)
        {
            if (user1.getUname().equals(user.getUname()))
            {
                return null;
            }
        }

        //convert the password to a secure one
        String passwordInsecure = user.getPassword();
        String generatedSecuredPasswordHash = PasswordHashing.generateStrongPasswordHash(passwordInsecure);

        //replace the original password with the secure password
        user.setPassword(generatedSecuredPasswordHash);

        userRepo.save(user);
        user.setPassword("");
        return user;
    }

    public String createToken(String username, Long id) {
        Claims claims = Jwts.claims().setSubject(username);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()
                .setClaims(claims)
                .claim("id", id)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, Base64.getEncoder().encodeToString(secretKey.getBytes()))
                .compact();
    }
}
