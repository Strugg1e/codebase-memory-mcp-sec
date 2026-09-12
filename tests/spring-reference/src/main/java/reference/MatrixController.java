package reference;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

// Test fixture only. No database, network or business operations.
@RestController
@RequestMapping(path={"/v1","/v2"}, method=RequestMethod.POST,
    params="a", headers="X-App", consumes="text/plain", produces="text/plain")
public class MatrixController {
    @GetMapping(path={"/a","/b"}, params="b", headers="X-Mode=on",
        consumes="application/json", produces="application/json")
    public String combinations(@RequestParam("a") String a) { return a; }

    @RequestMapping("/default")
    public String inheritedMethod() { return "fixture"; }

    @GetMapping(path="/equal", value="/equal")
    public String equalAliases() { return "fixture"; }

    @GetMapping("relative")
    public String relativePath() { return "fixture"; }

    @GetMapping
    public String emptyMethodPath() { return "fixture"; }
}
