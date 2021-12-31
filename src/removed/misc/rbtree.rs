#[derive(Clone, Copy, Debug)]
enum Color {
    Red,
    Black
}


//Err will never be returned under normal execution but added because data still fits in one byte so it doesnt matter...
enum RetAction {
    LChild,
    RChild,
    LRotate,
    RRotate,
    Exists,
    New,
    Unwind, //Unwind the call stack after insertion finishes
    Err,
}

#[derive(Debug)]
struct RBNode<T: std::fmt::Debug> {
    color: Color,
    key: usize,
    value: T,
    left: Option<Box<RBNode<T>>>,
    right: Option<Box<RBNode<T>>>
}

impl<T: std::fmt::Debug> RBNode<T> {
    pub fn insert(&mut self, key: usize, val: T) -> RetAction {
        if key == self.key {
            return RetAction::Exists;
        }
        if key > self.key {
            match self.right.take() {
                None => {
                    self.right = Some(
                        Box::new(
                            RBNode{
                                color: Color::Red,
                                key,
                                value: val,
                                left: None,
                                right: None
                            }
                        )
                    );
                    match self.color {
                        Color::Black => return RetAction::Unwind,
                        Color::Red => return RetAction::RChild
                    };
                },
                Some(mut p) => {
                    match p.insert(key, val) {
                        RetAction::Exists => return RetAction::Exists,
                        RetAction::Err => return RetAction::Err,
                        RetAction::Unwind => return RetAction::Unwind,
                        RetAction::New => {match (p.color, self.color) {(Color::Red, Color::Red) => {return RetAction::RChild;}, _ => {return RetAction::New;}};} //maybe unwind here?
                        RetAction::LChild => {
                            match p.left.take() {
                                Some(mut c) => {
                                    match self.left {
                                        Some(ref mut u) => {
                                            if let Color::Red = u.color {
                                                p.color = Color::Black;
                                                u.color = Color::Black;
                                                self.color = Color::Red;
                                                p.left = Some(c);
                                                self.right = Some(p);
                                                return RetAction::New;
                                            }
                                        },
                                        None => {}
                                    }
                                    p.left = c.right;
                                    c.right = Some(p);
                                    self.right = Some(c);
                                    return RetAction::LRotate;
                                },
                                None => return RetAction::Err,
                            }
                        },
                        RetAction::RChild => {
                            match p.right {
                                Some(_) => {
                                    match self.left {
                                        Some(ref mut u) => {
                                            if let Color::Red = u.color {
                                                p.color = Color::Black;
                                                u.color = Color::Black;
                                                self.color = Color::Red;
                                                self.right = Some(p);
                                                return RetAction::New;
                                            }
                                        },
                                        None => {}
                                    }
                                    self.right = Some(p);
                                    return RetAction::LRotate;
                                },
                                None => return RetAction::Err,
                            }
                        },
                        RetAction::LRotate => {
                            match p.right.take() {
                                Some(mut c) => {
                                    p.color = Color::Red;
                                    c.color = Color::Black;
                                    p.right = c.left;
                                    c.left = Some(p);
                                    self.right = Some(c);
                                    return RetAction::Unwind;
                                },
                                None => {return RetAction::Err;}
                            }
                        },
                        RetAction::RRotate => {
                            match p.left.take() {
                                Some(mut c) => {
                                    p.color = Color::Red;
                                    c.color = Color::Black;
                                    p.left = c.right;
                                    c.right = Some(p);
                                    self.right = Some(c);
                                    return RetAction::Unwind;
                                },
                                None => {return RetAction::Err;}
                            }
                        }
                    }
                }
            }
        }else {
            match self.left.take() {
                None => {
                    self.left = Some(
                        Box::new(
                            RBNode{
                                color: Color::Red,
                                key,
                                value: val,
                                left: None,
                                right: None
                            }
                        )
                    );
                    match self.color {
                        Color::Black => return RetAction::Unwind,
                        Color::Red => return RetAction::RChild
                    };
                },
                Some(mut p) => {
                    match p.insert(key, val) {
                        RetAction::Exists => return RetAction::Exists,
                        RetAction::Err => return RetAction::Err,
                        RetAction::Unwind => return RetAction::Unwind,
                        RetAction::New => {match (p.color, self.color) {(Color::Red, Color::Red) => {return RetAction::RChild;}, _ => {return RetAction::New;}};} //maybe unwind here?
                        RetAction::RChild => {
                            match p.right.take() {
                                Some(mut c) => {
                                    match self.right {
                                        Some(ref mut u) => {
                                            if let Color::Red = u.color {
                                                p.color = Color::Black;
                                                u.color = Color::Black;
                                                self.color = Color::Red;
                                                p.right = Some(c);
                                                self.left = Some(p);
                                                return RetAction::New;
                                            }
                                        },
                                        None => {}
                                    }
                                    p.right = c.left;
                                    c.left = Some(p);
                                    self.right = Some(c);
                                    return RetAction::RRotate;
                                },
                                None => return RetAction::Err,
                            }
                        },
                        RetAction::LChild => {
                            match p.left {
                                Some(_) => {
                                    match self.right {
                                        Some(ref mut u) => {
                                            if let Color::Red = u.color {
                                                p.color = Color::Black;
                                                u.color = Color::Black;
                                                self.color = Color::Red;
                                                self.left = Some(p);
                                                return RetAction::New;
                                            }
                                        },
                                        None => {}
                                    }
                                    self.left = Some(p);
                                    return RetAction::RRotate;
                                },
                                None => return RetAction::Err,
                            }
                        },
                        RetAction::LRotate => {
                            match p.right.take() {
                                Some(mut c) => {
                                    p.color = Color::Red;
                                    c.color = Color::Black;
                                    p.right = c.left;
                                    c.left = Some(p);
                                    self.left = Some(c);
                                    return RetAction::Unwind;
                                },
                                None => {return RetAction::Err;}
                            }
                        },
                        RetAction::RRotate => {
                            match p.left.take() {
                                Some(mut c) => {
                                    p.color = Color::Red;
                                    c.color = Color::Black;
                                    p.left = c.right;
                                    c.right = Some(p);
                                    self.left = Some(c);
                                    return RetAction::Unwind;
                                },
                                None => {return RetAction::Err;}
                            }
                        }
                    }
                }
            }
        }

    }
}
#[derive(Debug)]
pub struct RBTree<T: std::fmt::Debug> {
    root: Option<Box<RBNode<T>>>,
}

impl<T: std::fmt::Debug> RBTree<T> {
    pub fn new() -> RBTree<T> {
        RBTree{
            root: None,
        }
    }

    pub fn insert(&mut self, key: usize, value: T) -> Result<(), ()> {
        match self.root.take() {
            None => {
                self.root = Some(Box::new(
                    RBNode::<T> {
                        color: Color::Black,
                        key,
                        value,
                        left: None,
                        right: None,
                    }
                ))
            },
            Some(mut root) => {
                match root.insert(key, value) {
                    RetAction::LRotate => {
                        match root.right.take() {
                            Some(mut c) => {
                                root.color = Color::Red;
                                c.color = Color::Black;
                                root.right = c.left;
                                c.left = Some(root);
                                self.root = Some(c);
                            },
                            None => {return Err(());}
                        }
                    },
                    RetAction::RRotate => {
                        match root.left.take() {
                            Some(mut c) => {
                                root.color = Color::Red;
                                c.color = Color::Black;
                                root.left = c.right;
                                c.right = Some(root);
                                self.root = Some(c);

                            },
                            None => {return Err(());}
                        }
                    },
                    _ => {root.color = Color::Black; self.root = Some(root);}
                }
            }
        }
        return Ok(());
    }
}
