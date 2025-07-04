# [SAST](https://tryhackme.com/r/room/sast)

## Task 3 Manual Code Review

**Which of the mentioned functions is used in the project? (Include the parenthesis at the end of the function name)**

```shell
grep -r -n --include="*.php" "require(" /home/ubuntu/Desktop/simple-webapp/html
grep -r -n --include="*.php" "include(" /home/ubuntu/Desktop/simple-webapp/html
grep -r -n --include="*.php" "require_once(" /home/ubuntu/Desktop/simple-webapp/html
grep -r -n --include="*.php" "include_once(" /home/ubuntu/Desktop/simple-webapp/html
```

**How many instances of the function found in question 2 exist in your project's code?**

```shell
grep -r -n --include="*.php" "include(" /home/ubuntu/Desktop/simple-webapp/html | wc -l
```

**What file contains the vulnerable instance?**
**What line in the file found on the previous question is vulnerable to LFI?**

```shell
grep -r -n --include="*.php" "include(" /home/ubuntu/Desktop/simple-webapp/html | grep GET
```

## Task 4 Automated Code Review

**How many errors are reported after annotating the code as instructed in this task and re-running Psalm?**

* Edit `/home/ubuntu/Desktop/simple-webapp/html/db.php` and add this comments before `db_query` function:
  ```php
  /**
   * @psalm-taint-sink sql $query
   * @psalm-taint-specialize
   */
  function db_query($conn, $query){
  ```
* Rerun psalm:
  ```shell
  cd /home/ubuntu/Desktop/simple-webapp
  ./vendor/bin/psalm --no-cache --taint-analysis
  ```
  