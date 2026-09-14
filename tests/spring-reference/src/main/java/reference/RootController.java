package reference;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
@RestController
public class RootController {
    @GetMapping
    public String emptyPath() { return "fixture"; }

    @PostMapping("/root")
    public String directPath() { return "fixture"; }
}
