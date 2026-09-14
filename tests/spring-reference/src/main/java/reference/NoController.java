package reference;
import org.springframework.web.bind.annotation.GetMapping;
// Registered as a bean but NOT marked as a controller.
public class NoController {
    @GetMapping("/not-registered")
    public String notRegistered() { return "fixture"; }
}
