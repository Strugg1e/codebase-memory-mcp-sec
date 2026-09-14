/* Controlled return-dependency fixture, never read from the scanned repository. */
import java.lang.String;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class StringReference {
    static String sink(String value) { return value; }
    static String trimming(String input, String other, int start, int end) { return sink(input.trim()); }
    static String stripping(String input, String other, int start, int end) { return sink(input.strip()); }
    static String leading(String input, String other, int start, int end) { return sink(input.stripLeading()); }
    static String trailing(String input, String other, int start, int end) { return sink(input.stripTrailing()); }
    static String lower(String input, String other, int start, int end) { return sink(input.toLowerCase()); }
    static String upper(String input, String other, int start, int end) { return sink(input.toUpperCase()); }
    static String substringOne(String input, String other, int start, int end) { return sink(input.substring(start)); }
    static String substringTwo(String input, String other, int start, int end) { return sink(input.substring(start,end)); }
    static String concatenating(String input, String other, int start, int end) { return sink(input.concat(other)); }
    static String repeating(String input, String other, int start, int end) { return sink(input.repeat(start)); }
    static String replacing(String input, String other, int start, int end) { return sink(input.replace("x",other)); }
    static String identity(String input, String other, int start, int end) { return sink(input.toString()); }
    static String overwritten(String input, String other, int start, int end) { input="fixed"; return sink(input.strip()); }
    static String chained(String input, String other, int start, int end) { return sink(input.trim().substring(start).concat(other)); }

    static String run(String name, String input, String other, int start, int end) {
        switch(name) {
            case "trimming": return trimming(input,other,start,end);
            case "stripping": return stripping(input,other,start,end);
            case "leading": return leading(input,other,start,end);
            case "trailing": return trailing(input,other,start,end);
            case "lower": return lower(input,other,start,end);
            case "upper": return upper(input,other,start,end);
            case "substringOne": return substringOne(input,other,start,end);
            case "substringTwo": return substringTwo(input,other,start,end);
            case "concatenating": return concatenating(input,other,start,end);
            case "repeating": return repeating(input,other,start,end);
            case "replacing": return replacing(input,other,start,end);
            case "identity": return identity(input,other,start,end);
            case "overwritten": return overwritten(input,other,start,end);
            case "chained": return chained(input,other,start,end);
            default: throw new IllegalArgumentException(name);
        }
    }
    public static void main(String[] args) {
        String[] names={"trimming","stripping","leading","trailing","lower","upper", "substringOne",
            "substringTwo","concatenating","repeating","replacing","identity","overwritten","chained"};
        for (String name:names) {
            String[] outputs={run(name," aBc x ","Z",1,4),run(name," qRs y ","Z",1,4),
                run(name," aBc x ","W",1,4),run(name," aBc x ","Z",2,4),run(name," aBc x ","Z",1,5)};
            System.out.print(name);
            for (String value:outputs) System.out.print("\t"+Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
            System.out.println();
        }
    }
}
