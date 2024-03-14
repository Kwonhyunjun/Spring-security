package org.example.springjwt.Controller;

import lombok.extern.slf4j.Slf4j;
import org.example.springjwt.dto.JoinDto;
import org.example.springjwt.service.JoinService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService){
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDto joinDto) {
        log.info("----------------Join Controller-------------------------");
        joinService.joinProcess(joinDto)    ;
        return "ok";
    }
}
