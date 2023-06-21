---
title: "Template"
draft: true
description: ""
categories: ["template"]
tags: []
date: 2023-06-22T00:03:09+05:30
summary: New post to test theme features
coverAlt: "An example cover image"
coverCaption: "This is an example cover image with a caption"
---

# Heading 1

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At urna condimentum mattis pellentesque id nibh tortor. Sed felis eget velit aliquet sagittis id consectetur purus ut. Pellentesque massa placerat duis ultricies lacus sed turpis tincidunt id. Ultrices neque ornare aenean euismod. Amet purus gravida quis blandit turpis cursus. Massa enim nec dui nunc mattis enim ut tellus elementum. Nisl rhoncus mattis rhoncus urna neque viverra justo nec ultrices. Nunc scelerisque viverra mauris in aliquam sem fringilla ut morbi. Fusce id velit ut tortor pretium viverra suspendisse potenti nullam. Ac turpis egestas maecenas pharetra convallis posuere.

Bug icon -> {{< icon "bug" >}}

Embedded yt video
{{< youtube _tV5LEBDs7w >}}

Obsidian style callouts
{{< alert "" >}}
**Warning!** This action is destructive!
{{< /alert >}}

## Sub heading 1

Convallis a cras semper auctor neque vitae tempus quam. Amet porttitor eget dolor morbi non arcu. Aliquet eget sit amet tellus cras adipiscing enim eu turpis. Eu non diam phasellus vestibulum lorem sed risus ultricies. Donec ultrices tincidunt arcu non sodales neque sodales ut etiam. Imperdiet proin fermentum leo vel orci porta non pulvinar. Vel quam elementum pulvinar etiam non quam. Nulla posuere sollicitudin aliquam ultrices sagittis orci a scelerisque purus. Penatibus et magnis dis parturient. Sed enim ut sem viverra. Sagittis aliquam malesuada bibendum arcu vitae elementum curabitur vitae. Vestibulum rhoncus est pellentesque elit ullamcorper dignissim.

Normal codeblock

```python
x = 1
var = x + 10
print(f"Hello world: {var}")
```

Highlighted codeblock

`< highlight python "linenos=table,hl_lines=3 5-6" >`
{{< highlight python "linenos=table,hl_lines=3 5-6" >}}

x = 1
var = x + 10
print(f"Hello world: {var}")

print("Highlight")
print("this")
print("Not this")

{{< /highlight >}}

> Quote along with citing
> — <cite>Abraxas</cite>

Keyboard buttons -> enclose in `kbd` tags: <kbd>CTRL</kbd>+<kbd>ALT</kbd>+<kbd>Delete</kbd>

{{< button href="#button" target="_self" >}}
This is a button
{{< /button >}}

### Something Something

![Alt text](nature.jpg "Image caption")

`![Alt text](nature.jpg "Image caption")`

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At urna condimentum mattis pellentesque id nibh tortor. Sed felis eget velit aliquet sagittis id consectetur purus ut. Pellentesque massa placerat duis ultricies lacus sed turpis tincidunt id. Ultrices neque ornare aenean euismod. Amet purus gravida quis blandit turpis cursus. Massa enim nec dui nunc mattis enim ut tellus elementum. Nisl rhoncus mattis rhoncus urna neque viverra justo nec ultrices. Nunc scelerisque viverra mauris in aliquam sem fringilla ut morbi. Fusce id velit ut tortor pretium viverra suspendisse potenti nullam. Ac turpis egestas maecenas pharetra convallis posuere.

-   List 1
    1. Sub-List 1
    2. Sub-List 2
-   List 2
-   List 3
-   List 4

Embeded gist
{{< gist AbraXa5 4e51b2be2a23b42f92524ff3506c75fb >}}

## Filler Heading

Consectetur libero id faucibus nisl tincidunt eget nullam non. Nulla facilisi cras fermentum odio eu feugiat. Vel quam elementum pulvinar etiam. Placerat vestibulum lectus mauris ultrices eros in cursus. Id consectetur purus ut faucibus. Hendrerit dolor magna eget est lorem ipsum dolor. Gravida neque convallis a cras semper auctor neque. Sed euismod nisi porta lorem mollis aliquam ut porttitor leo. Ut consequat semper viverra nam libero. Mattis ullamcorper velit sed ullamcorper morbi tincidunt. In egestas erat imperdiet sed euismod nisi. Nullam eget felis eget nunc lobortis. Pellentesque elit eget gravida cum sociis natoque penatibus. Et molestie ac feugiat sed lectus vestibulum mattis ullamcorper.

Ut venenatis tellus in metus. Netus et malesuada fames ac turpis egestas. Arcu dui vivamus arcu felis. Eu mi bibendum neque egestas congue quisque. Sit amet nisl suscipit adipiscing. Quam id leo in vitae turpis massa. Felis donec et odio pellentesque diam. Magna fermentum iaculis eu non diam phasellus vestibulum lorem sed. Vel pharetra vel turpis nunc eget. Arcu vitae elementum curabitur vitae nunc. Erat velit scelerisque in dictum non consectetur. Pharetra convallis posuere morbi leo urna. Quis blandit turpis cursus in hac habitasse platea dictumst quisque. Elit ullamcorper dignissim cras tincidunt lobortis feugiat vivamus at.

Graphs using mermaid
{{< mermaid >}}
graph LR;
A[Point1];
A-->B[Point2];
B-->C[Point3];
{{< /mermaid >}}

## Found a typo?

If you come across any errors, such as typos or sentences that could be improved, or if you have any suggestions for updates to this blog post, please create a new [pull request](https://github.com/AbraXa5/personal-blog/tree/main/content/blog) to propose your changes. Your contributions are greatly appreciated.

> This can also be done by clicking the edit icon besides the title
