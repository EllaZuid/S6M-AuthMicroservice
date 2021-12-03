package AuthMicroservice.controller;

import AuthMicroservice.DTO.TokenDTO;
import AuthMicroservice.entity.User;
import AuthMicroservice.logic.AuthLogic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthLogic auth;

    @Autowired
    public AuthController(AuthLogic test)
    {
        this.auth = test;
    }

    @GetMapping()
    public String getTest()
    {
        return "Dit is de authcontroller";
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody User user) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (user.getUname().isBlank() || user.getPassword().isBlank()){
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        TokenDTO token = this.auth.login(user);
        if (token != null)
            return new ResponseEntity(token, HttpStatus.OK);
        else
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody User user) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        User generalUser = this.auth.register(user);
        if (generalUser != null)
            return new ResponseEntity(HttpStatus.OK);
        else
            return new ResponseEntity(HttpStatus.BAD_REQUEST);

    }


}
